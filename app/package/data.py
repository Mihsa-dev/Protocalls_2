import struct
from dataclasses import dataclass
from enum import Enum
from typing import List


# типы запросов
class QueryType(int, Enum):
    A = 1
    NS = 2
    PTR = 12
    AAAA = 28


# класс запроса (Интернет)
class QueryClass(int, Enum):
    IN = 1


# класс с полями заголовка ДНС ответа
@dataclass
class DNSHeader:
    id: int  # id запроса
    flags: int  # флаги
    qd_count: int  # количество вопросов
    an_count: int  # количество ответов в записи
    ns_count: int  # количество авторитетных ответов
    ar_count: int  # количество дополнительных записей


# класс с полями вопроса ДНС
@dataclass
class DNSQuestion:
    q_name: str  # имя адреса
    q_type: QueryType  # тип запроса
    q_class: QueryClass  # класс запроса


# класс с полями ресурса ДНС (последние три поля в пакете ДНС)
@dataclass
class DNSResourceRecord:
    r_name: str  # имя домена
    r_type: QueryType  # тип запроса
    r_class: QueryClass  # класс запроса
    r_ttl: int  # время жизни пакета
    rd_length: int  # длина данных
    r_data: str  # данные


# класс со структурой всего пакета ДНС
@dataclass
class DNSPackage:
    data: bytes
    _pointer: int = 0
    header: DNSHeader = None
    questions: List[DNSQuestion] = None
    answer_records: List[DNSResourceRecord] = None
    authoritative_records: List[DNSResourceRecord] = None
    additional_records: List[DNSResourceRecord] = None

    def __post_init__(self):
        self.questions = []
        self.answer_records = []
        self.authoritative_records = []
        self.additional_records = []
        self._init_header()
        self._init_questions()
        self._init_resource_records()

    # считываем заголовок
    def _init_header(self):
        step = 12  # размер заголовка в байтах
        self.header = DNSHeader(*struct.unpack("!6H", self.data[:step]))
        self._pointer += step

    # считываем вопрос
    def _init_questions(self):
        step = 4  # размер запроса в байтах
        for _ in range(self.header.qd_count):
            self.questions.append(
                DNSQuestion(
                    self._parse_name(),
                    *struct.unpack(
                        "!HH", self.data[self._pointer: self._pointer + step]
                    ),
                )
            )
            self._pointer += step

    # считыаем ресурсные записи
    def _init_resource_records(self):
        rrs = (
            (self.answer_records, self.header.an_count),
            (self.authoritative_records, self.header.ns_count),
            (self.additional_records, self.header.ar_count),
        )
        [self._init_resource_record(*rr) for rr in rrs]

    def _init_resource_record(self, buf, length):
        step = 10
        for _ in range(length):
            r_name = self._parse_name()
            r_type, r_class, r_ttl, rd_length = struct.unpack(
                "!HHIH", self.data[self._pointer: self._pointer + step]
            )
            self._pointer += step
            r_data = self._parse_resource_body(r_type, rd_length)
            buf.append(
                DNSResourceRecord(r_name, r_type, r_class, r_ttl, rd_length, r_data)
            )

    # считываем имя домена
    def _parse_name(self):
        name_list = []
        position = self._pointer
        flag = False
        while True:
            # если значение байта больше 63, то он указывает смещение на другую позицию в сообщении
            if self.data[position] > 63:
                if not flag:
                    self._pointer = position + 2
                    flag = True
                position = ((self.data[position] - 192) << 8) + self.data[position + 1]
                continue
            # иначе началась следующая часть сообщения длины меньше либо рвной 63 байт
            else:
                length = self.data[position]
                if length == 0:
                    if not flag:
                        self._pointer = position + 1
                    break
                position += 1
                name_list.append(self.data[position: position + length])
                position += length
        name = ".".join([i.decode("cp1251") for i in name_list])
        return name

    # считываем ресурсные записи в зависимости от типа запроса
    def _parse_resource_body(self, r_type, rd_length):
        if r_type == QueryType.A.value:
            ipv4_address = struct.unpack(
                f"!{rd_length}B",
                self.data[self._pointer: self._pointer + rd_length],
            )
            data = ".".join(str(octet) for octet in ipv4_address)
            self._pointer += rd_length
        elif r_type == QueryType.NS.value or r_type == QueryType.PTR.value:
            data = self._parse_name()
        elif r_type == QueryType.AAAA.value:
            ipv6_address = struct.unpack(
                f"!{rd_length // 2}H",
                self.data[self._pointer: self._pointer + rd_length],
            )
            data = ":".join(str(hex(octet))[2:] for octet in ipv6_address)
            self._pointer += rd_length
        else:
            raise Exception(f"Unsupported query type={r_type}")
        return data