import signal
import socket

from app.package import builder
from app import dependencies, resolver
from app.cacher import Cacher
from app.package.data import DNSPackage

settings = dependencies.get_server_settings()


class Server:
    def __init__(self):
        # подключаемся к сокету, который будем прослушивать
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.bind((settings["server_ip"], settings["server_port"]))
        self._init_cacher()
        self._handle_flag = True
        signal.signal(signal.SIGINT, self._close)

    def _init_cacher(self):
        # создаем кэш
        self._cacher = Cacher(settings["cache_filepath"], settings["clean_period"])
        self._cacher.load()
        self._cacher.start()

    def run(self):
        # получаем запросы от клиента
        while self._handle_flag:
            request, address = self._server_socket.recvfrom(settings["request_size"])
            self._handle_client(request, address)

    # Обрабатываем запросы клиента
    def _handle_client(self, request: bytes, address: str):
        request_package = DNSPackage(request)

        total_a_records = []

        for question in request_package.questions:
            q_request = builder.get_request(
                request_package.header.id,
                question.q_name,
                question.q_type,
                question.q_class,
            )
            # проверяем, есть ли такой запрос уже в кэше
            if (
                    cached_info := self._cacher.get(question.q_name, question.q_type)
            ) is None:
                # если запроса нет, то пытаемся получить ответ от днс сервера, пересылая ему запрос
                try:
                    answer = resolver.resolve(q_request=q_request)
                except Exception as e:
                    print(e)
                    response = builder.get_unsupported_response(q_request[:2])
                    self._server_socket.sendto(response, address)
                    return

                a_records = answer.answer_records
                self._cacher.add(question.q_name, question.q_type, a_records)
            # иначе достаем запрос из кэша
            else:
                print("from cache")
                _, a_records = cached_info

            total_a_records += a_records

        response = builder.get_response(
            request_package.header, request_package.questions, total_a_records
        )
        self._server_socket.sendto(response, address)

    # Останавливаем работу сервера
    def _close(self, _, __):
        self._handle_flag = False
        self._server_socket.close()
        self._cacher.save()
        self._cacher.close()