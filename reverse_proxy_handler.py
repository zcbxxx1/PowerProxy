#!/usr/bin/env python3
import argparse
import logging
import logging.handlers
import os
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import queue
from typing import Optional, Tuple


class ProxyHandler:

    shutdown_flag = threading.Event()
    kill_reverse = False

    # SSL/TLS (for connection w/ remote proxies)
    ssl_context = None
    # Paths to cert files
    ssl_cert = None
    ssl_key = None

    def __init__(self, proxy_addr, proxy_port, listen_addr, listen_port):

        # Server that handles clients（本地 SOCKS 客户端）
        self.client_address = proxy_addr
        self.client_port = int(proxy_port)
        self.client_listener_sock = None
        # Server that handles remote proxies（反向代理客户端）
        self.reverse_address = listen_addr
        self.reverse_port = int(listen_port)
        self.reverse_listener_sock = None

        # Active connections from reverse proxies (sockets)
        self.reverse_sockets = queue.Queue()

    @staticmethod
    def _safe_close(sock: Optional[socket.socket]) -> None:
        """安全关闭 socket，避免在关闭过程中抛出异常导致流程中断。"""
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # 可能已关闭/未连接，忽略即可
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # SSL/TLS for connection with remote proxies
    def set_ssl_context(self, certificate=None, private_key=None, verify=True):

        # 创建 SSL 上下文，优先使用系统默认 CA；默认 verify_mode 为 CERT_REQUIRED
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
        )

        # 不校验 hostname（反向代理一般非公开域名）
        ssl_context.check_hostname = False

        # 保存证书与私钥路径
        if certificate:
            self.ssl_cert = os.path.abspath(certificate)
            if private_key:
                self.ssl_key = os.path.abspath(private_key)
        else:
            self.ssl_cert, self.ssl_key = create_ssl_cert()

        ssl_context.load_cert_chain(self.ssl_cert, keyfile=self.ssl_key)

        # 可选：放宽证书验证（便于自签证书）
        if not verify:
            ssl_context.verify_mode = ssl.CERT_OPTIONAL
        
        self.ssl_context = ssl_context
        logger.debug("[&] SSL enabled")

    # Master thread
    def serve(self):

        # 捕获 Ctrl-C / SIGTERM，优雅退出
        signal.signal(signal.SIGINT, self.sig_handler)
        signal.signal(signal.SIGTERM, self.sig_handler)

        # 启动线程：轮询检测反向代理连接是否存活
        connection_poller_t = threading.Thread(
            target=self.poll_reverse_connections,
            name="connection_poller"
        )
        connection_poller_t.start()

        if not self.ssl_context:
            logger.warning("[!] WARNING: SSL context not set. Connections to reverse proxies will not be encrypted!")

        try:
            # 监听来自反向代理的连接
            reverse_listener = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            reverse_listener.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            reverse_listener.settimeout(0.5)
            reverse_listener.bind((self.reverse_address, self.reverse_port))
            self.reverse_listener_sock = reverse_listener

            # 单独线程接入反向代理连接
            reverse_listener_t = threading.Thread(
                target=self.listen_for_reverse,
                args=[reverse_listener, ],
                name="reverse_listener"
            )
            reverse_listener_t.start()
            logger.info("Listening for reverse proxies on {}:{}".format(
                self.reverse_address, self.reverse_port))

            # 监听本地客户端
            client_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_listener.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_listener.settimeout(0.5)
            client_listener.bind((self.client_address, self.client_port))
            self.client_listener_sock = client_listener

            client_listener_t = threading.Thread(
                target=self.listen_for_client,
                args=[client_listener, ],
                name="client_listener"
            )
            client_listener_t.start()
            logger.info("Listening for clients on {}:{}".format(
                self.client_address, self.client_port))

            # 保持主线程存活，等待退出信号
            while not self.shutdown_flag.is_set():
                time.sleep(0.5)

        except Exception as e:
            logger.error("[!] ERROR in master thread: {}".format(e))
            raise e
        finally:
            self.kill_local_process()

    def sig_handler(self, signal_number, stack_frame):

        if signal_number == 2:
            logger.warning("\n[!] SIGINT received")
        else:
            logger.warning("\n[!] Signal received: {}".format(signal_number))
        
        logger.info("Shutting down...")
        self.kill_local_process()


    # Close all sockets and threads, then exit. Does not send kill signal to remote machines
    def kill_local_process(self):

        #logger.info("Shutting down!")
        self.shutdown_flag.set()
        self._safe_close(self.reverse_listener_sock)
        self._safe_close(self.client_listener_sock)

        if self.kill_reverse:
            self.kill_reverse_process()

        while not self.reverse_sockets.empty():
            s = self.reverse_sockets.get()
            self._safe_close(s)
        
        sys.exit(0)

    # Send "KILL" message to reverse proxies
    def kill_reverse_process(self, timeout=1, address=None):
        # TODO - Use address arg to only kill hosts at a given address

        message = 'KILL'.encode()

        # Track proxies that reply 'DEAD' (i.e. confirm shutdown)
        sock_count = self.reverse_sockets.qsize()
        dead_count = 0

        if sock_count:
            logger.debug("[!] Killing {} reverse proxies!".format(sock_count))

        while not self.reverse_sockets.empty():
            s = self.reverse_sockets.get()
            s.settimeout(timeout)
            try:
                s.send(message)
                reply = s.recv(2048)
                if len(reply) == 0:
                    # connection already closed
                    self._safe_close(s)
                    continue
                elif reply == b'DEAD':
                    dead_count += 1
                    self._safe_close(s)
                    continue
                else:
                    # try one more time, since shit's weird
                    reply += s.recv(2048)
                    if reply == b'DEAD':
                        dead_count += 1
                        self._safe_close(s)
                        continue
            except socket.timeout:
                pass
            finally:
                self._safe_close(s)

        if sock_count:
            logger.info("'KILL' message sent to {} proxies. {} confirmed 'DEAD'".format(sock_count, dead_count))


    # Listen for incoming connections from reverse proxies
    def listen_for_reverse(self, listen_socket, backlog=20):

        # 开始监听反向代理连接
        listen_socket.listen(backlog)

        while not self.shutdown_flag.is_set():

            # 接收连接（先是明文连接）
            try:
                clear_socket, __ = listen_socket.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if e.errno == 9:
                    return
                else:
                    raise

            # 如果启用了 SSL，则升级为加密连接
            if self.ssl_context:
                reverse_socket = self.ssl_context.wrap_socket(
                    clear_socket, server_side=True)
            else:
                reverse_socket = clear_socket

            # 保存 socket 以供客户端连接使用
            self.reverse_sockets.put(reverse_socket)

    # Listen for proxy clients
    def listen_for_client(self, srv_sock, backlog=10):

        srv_sock.listen(backlog)

        while not self.shutdown_flag.is_set():
            try:
                client_socket, address = srv_sock.accept()
            except socket.timeout:
                continue
            # When shutdown signalled, socket is destroyed at some point, raises OSerror errno9
            except OSError as e:
                if e.errno == 9:
                    return
                else:
                    raise


            address = f"{address[0]}:{address[1]}"
            logger.info("[*] Client connected from {}".format(address))

            # 每个客户端由独立线程进行转发
            forward_conn_t = threading.Thread(
                target=self.forward_connection,
                args=[client_socket, ],
                name=f"forward_client_{address}",
                daemon=True,
            )
            forward_conn_t.start()

    # Proxy connection between client and remote
    def forward_connection(self, client_socket, reverse_socket=None, wait=5, max_fails=10):

        reverse_socket = self.get_available_reverse(wait=wait, max_attempts=max_fails)
        
        # 获取客户端和反向代理的基本信息用于日志
        client_addr = client_socket.getpeername()
        reverse_addr = reverse_socket.getpeername()

        # debug message
        logger.debug("[_] Tunneling {} through {}".format(client_addr, reverse_addr))

        # 通知反向代理开始转发
        self.wake_reverse(reverse_socket)

        #######################
        # FORWARDING
        ############

        reverse_socket.setblocking(False)
        client_socket.setblocking(False)

        # 进入转发循环：select 监视两个 socket
        while not self.shutdown_flag.is_set():
            receivable, __, __ = select.select([reverse_socket, client_socket], [], [])

            for sock in receivable:

                if sock is reverse_socket:
                    data = b''
                    while True:
                        try:
                            buf = reverse_socket.recv(2048)
                        except (BlockingIOError, ssl.SSLWantReadError):
                            break
                        except Exception as e:
                            logger.debug(
                                "[!] Error receiving from remote: {}".format(e))
                            break

                        if len(buf) == 0:
                            break
                        else:
                            data += buf
                    if len(data) != 0:
                        client_socket.sendall(data)
                    else:
                        logger.error("[!] Reverse proxy disconnected while forwarding!")
                        self._safe_close(client_socket)
                        self._safe_close(reverse_socket)
                        return

                if sock is client_socket:
                    data = b''
                    while True:
                        try:
                            buf = client_socket.recv(2048)
                        except BlockingIOError:
                            break
                        except Exception as e:
                            logger.debug(
                                "[!] Error receiving from client: {}".format(e))
                            break

                        if len(buf) == 0:
                            break
                        else:
                            data += buf
                    if len(data) != 0:
                        reverse_socket.sendall(data)
                    else:
                        # Connection is closed
                        logger.debug("[x] Closing connection to client {}. Forwarding complete".format(client_addr))
                        self._safe_close(client_socket)
                        self._safe_close(reverse_socket)
                        return


    # Return socket connected to reverse proxy
    def get_available_reverse(self, wait=1, max_attempts=5):

        reverse_socket = None

        try:
            reverse_socket = self.reverse_sockets.get()
        # Don't know the specific exception when getting from empty queue (TODO)
        except Exception as e:

            logger.error("[!] No reverse proxies available: {}".format(e))
            logger.debug(
                "Waiting max {} seconds for a proxy".format(wait * max_attempts))

            for __ in range(max_attempts - 1):
                time.sleep(wait)
                try:
                    reverse_socket = self.reverse_sockets.get()
                    break
                except:
                    pass

            if not reverse_socket:
                logger.error("[!] No proxies showed up! Killing process and exiting...")
                self.kill_local_process()
                raise
        
        return reverse_socket

    # Check on waiting reverse proxies to see if connection still open
    def poll_reverse_connections(self, timeout=0.2, wait_time=1):

        # Track connections (value is a set())
        self.reverse_connections = dict()

        # TODO: Queue 的出入顺序会影响检测的公平性，这里仅做简单轮询
         
        while not (self.shutdown_flag.is_set()):
            
            if self.reverse_sockets.empty():
                time.sleep(wait_time)
                continue
            
            # 取出一个连接进行存活检测
            reverse_sock = self.reverse_sockets.get()
            address = reverse_sock.getpeername()[0]
            sock_id = id(reverse_sock)

            connection_count = self.reverse_sockets.qsize()

            # 保存原始超时时间，避免影响正常数据传输
            old_timeout = reverse_sock.gettimeout()
            # 使用短超时进行探测
            reverse_sock.settimeout(timeout)

            try:
                data = reverse_sock.recv(2048)

                # 收到空数据，表示连接已断开
                if len(data) == 0:
                    try:
                        # Close socket
                        reverse_sock.shutdown(socket.SHUT_RDWR)         # Disallow further reads and writes
                        reverse_sock.close()
                    except OSError as e:
                        # Socket not connected error
                        if e.errno == 57:
                            pass
                        else:
                            logger.error(e)

                    # Remove socket (and possibly host) from reverse_connections
                    self.reverse_connections[address].remove(sock_id)
                    
                    logger.debug("[-] Connection to proxy {} lost ({} remain)".format(address, connection_count))

                    # Remove host if there are no remaining connections
                    if len(self.reverse_connections[address]) == 0:
                        del self.reverse_connections[address]
                        logger.info("[-] Reverse proxy {} lost".format(address))

 
            # timeout 表示连接仍然存活
            except socket.timeout:

                # 已知地址：新增连接计数
                if self.reverse_connections.get(address, False):
                    if sock_id not in self.reverse_connections[address]:
                        self.reverse_connections[address].add(sock_id)
                        logger.debug("[+] Connection to proxy {} added ({} total)".format(address, (connection_count + 1)))

                # 新地址：首次登记
                else:
                    self.reverse_connections[address] = set()
                    self.reverse_connections[address].add(sock_id)
                    logger.info("[+] New reverse proxy: {}".format(address))
                    logger.debug("[+] Connection to proxy {} added (1 total)".format(address))

                # 恢复超时并放回队列
                reverse_sock.settimeout(old_timeout)
                self.reverse_sockets.put(reverse_sock)
            



        return

    # Send 'WAKE' message to waiting reverse proxy. Return reply message
    def wake_reverse(self, reverse_sock, max_attempts=5):

        reply = None 

        reverse_sock.send("WAKE".encode())
        data = reverse_sock.recv(2048)

        i = 0
        while not (len(data) == 4):
            data += reverse_sock.recv(2048)
            if i == max_attempts:
                break
            else:
                i += 1

        if data != b"WOKE":
            logger.error("[!] Unexpected reply from reverse proxy: {}".format(data))
            # raise
        else:
            reply = 'WOKE'
        return reply

# Use OpenSSL to create a server cert. Returns (cert_path, key_path)
def create_ssl_cert(cert_path=None, key_path=None, temporary=True) -> Tuple[str, str]:

    # 创建证书和私钥输出路径
    if temporary:
        logger.info("[&] Creating temporary SSL cert")
        domain = "example.local"
        __, cert_path = tempfile.mkstemp()
        __, key_path = tempfile.mkstemp()
        logger.info("Path to temporary SSL cert: {}".format(cert_path))
        logger.info("Path to temporary SSL key: {}".format(key_path))
    else:
        logger.info("[&] Creating SSL cert")

        # OpenSSL 需要 CN（域名）
        try:
            domain = os.uname().nodename
        except:
            domain = "example.local"

        # 生成证书路径
        if cert_path != None:
            if os.path.exists(cert_path):
                temp_cert_path = os.path.join(tempfile.gettempdir(), os.path.splitext(sys.argv[0])[0]) + ".pem"
                logger.error("[!] File at {} already exists! Saving cert to {}".format(cert_path, temp_cert_path))
                cert_path = temp_cert_path
            cert_path = os.path.abspath(cert_path)
        else:
            if os.access(os.getcwd(), os.W_OK):
                cert_path = os.path.join(os.getcwd(), "cert.pem")
            else:
                cert_path = os.path.join(tempfile.gettempdir(), "cert.pem")

        # 生成私钥路径
        if key_path !=  None:
            if os.path.exists(key_path):
                temp_key_path = os.path.join(tempfile.gettempdir(), os.path.splitext(sys.argv[0])[0]) + ".key"
                logger.error("[!] File at {} already exists! Saving cert to {}".format(key_path, temp_key_path))
                key_path = temp_key_path
            key_path = os.path.abspath(key_path)
        else:
            if os.access(os.getcwd(), os.W_OK):
                key_path = os.path.join(os.getcwd(), "cert.key")
            else:
                key_path = os.path.join(tempfile.gettempdir(), "cert.key")
 
        logger.info("Path to SSL cert: {}".format(cert_path))
        logger.info("Path to SSL key: {}".format(key_path))
    
    # 调用 OpenSSL 生成证书
    openssl = f'openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -batch -subj /CN={domain}'
    openssl_result = subprocess.run(openssl.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if openssl_result.returncode == 0:
        logger.debug("[&] SSL cert created successfully!")
    else:
        logger.warning("[!] OpenSSL returncode not zero! Possible error!")

    return cert_path, key_path


def main():

    # Address/port for server(s)
    reverse_address = args.reverse_address
    reverse_port = args.reverse_port
    client_address = args.client_address
    client_port = args.client_port

    # Instantiate ProxyHandler
    proxy_handler = ProxyHandler(
        client_address, client_port, reverse_address, reverse_port)

    # Set SSL for ProxyHandler (or don't)
    ssl_cert = args.cert
    ssl_key = args.key
    
    if args.create_cert:
        ssl_cert, ssl_key = create_ssl_cert(cert_path=ssl_cert, key_path=ssl_key, temporary=False)
    
    if not args.no_encrypt:
        proxy_handler.set_ssl_context(
            certificate=ssl_cert,
            private_key=ssl_key,
            verify=args.verify_certs
        )

    # Set kill_reverse property for remote termination of proxies
    if args.kill_reverse:
        proxy_handler.kill_reverse = True

    proxy_handler.serve()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ##########
    # Listener options
    #####
    # Listening for connections from reverse proxies
    parser.add_argument(
        "-p",
        "--reverse-port",
        default=443,
        type=int,
        help="Port to listen for reverse proxies connecting"
    )
    parser.add_argument(
        "-a",
        "--reverse-address",
        default="",
        help="Listen for reverse proxies on a specific address"
    )
    # Listening for connections from SOCKS clients
    parser.add_argument(
        "-P",
        "--client-port",
        default=1080,
        type=int,
        help="Port to listen for clients connecting"
    )
    parser.add_argument(
        "-A",
        "--client-address",
        default="127.0.0.1",
        help="IP address to listen for clients connecting"
    )

    ##########
    # Reverse proxy interaction options
    #####

    parser.add_argument(
        "--kill-reverse",
        action="store_true",
        help="Signal reverse proxies to shutdown when handler closes"
    )

    ##########
    # SSL/TLS options
    #####
    parser.add_argument(
        "-c",
        "--cert",
        default=None,
        help="Path to SSL certificate"
    )
    parser.add_argument(
        "-k",
        "--key",
        default=None,
        help="Path to SSL private key"
    )
    parser.add_argument(
        "--create-cert",
        action="store_true",
        help="Create SSL cert/key (requires OpenSSL)"
    )
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="Don't encrypt connections with remote proxies"
    )
    parser.add_argument(
        "--verify-certs",
        default=False,
        action="store_true",
        help="Use ssl.CERT_REQUIRED for SSL/TLS context (default: ssl.CERT_OPTIONAL)"
    )

    ##########
    # Output & logging options
    #####
    parser.add_argument(
        "-l",
        "--logfile",
        help="Log file"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output and logging"
    )

    # Parse arguments
    args = parser.parse_args()

    ##########
    # LOGGING
    #####
    global logger

    # 创建无大小限制的队列，由 QueueHandler 异步处理日志
    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)

    # Set logger to use QueueHandler
    logger = logging.getLogger()
    logger.addHandler(queue_handler)
    # logger.setLevel(logging.DEBUG)

    # LOG HANDLERS

    # Console logger - "console_logger"
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('{message}', style='{')
    console_handler.setFormatter(console_formatter)
    if args.verbose:
        # console_handler.setLevel("DEBUG")
        logger.setLevel("DEBUG")
    else:
        # console_handler.setLevel("INFO")
        logger.setLevel("INFO")

    # File logger - "file_logger"
    if args.logfile:
        file_handler = logging.FileHandler(filename=args.logfile)
    else:
        file_handler = logging.NullHandler()
    file_formatter = logging.Formatter(
        '[{threadName}] - {asctime} - {message}', style='{')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel('DEBUG')

    # Start listening for logs
    queue_listener = logging.handlers.QueueListener(
        log_queue, console_handler, file_handler)
    queue_listener.start()

    #####
    # /LOGGING
    ##########

    # 保证程序退出时停止日志监听器
    try:
        main()
    finally:
        queue_listener.stop()
