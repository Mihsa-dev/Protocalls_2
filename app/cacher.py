import os
import pickle
import time
from datetime import datetime
from threading import Lock, Thread
from typing import Dict, List, Tuple

from app.package.data import DNSResourceRecord, QueryType


# Класс для работы с кэшем
class Cacher:
    def __init__(self, path, clean_period):
        self.path: str = path
        self.buffer: Dict[
            str,
            Dict[QueryType, Tuple[datetime, List[DNSResourceRecord]]],
        ] = {}
        self.cleaner = Thread(target=self._cleaner, args=(clean_period,), daemon=True)
        self.lock = Lock()

    # Выгружаем все данные из файла с кэшем
    def load(self):
        try:
            if os.path.getsize(self.path) > 0:
                with open(self.path, "rb") as file:
                    self.buffer = pickle.load(file)
        except FileNotFoundError:
            open(self.path, "a").close()
            print(f"Created file {self.path}.")

    # Запускаем поток, который будет очищать кэш
    def start(self):
        self.cleaner.start()

    # Добавление записей в буффер с кэшем
    def add(
            self,
            q_name: str,
            q_type: QueryType,
            answer_records: List[DNSResourceRecord],
    ):
        if q_name not in self.buffer:
            self.buffer[q_name] = {}
        if q_type not in self.buffer[q_name]:
            self.buffer[q_name][q_type] = datetime.now(), answer_records

    # Получение записей из буффера с кэшем
    def get(self, q_name: str, q_type: QueryType):
        if q_name in self.buffer and q_type in self.buffer[q_name]:
            if self._is_late_records(q_name, q_type):
                self._clean_buffer(q_name, q_type)
                return None
            return self.buffer[q_name][q_type]

    # Удаление истекших записей из кэша
    def _cleaner(self, period):
        while True:
            items = list(self.buffer.items())
            for q_name, d in items:
                keys = list(d.keys())
                for q_type in keys:
                    if self._is_late_records(q_name, q_type):
                        self._clean_buffer(q_name, q_type)

            time.sleep(period)

    # Очистка буффера
    def _clean_buffer(self, q_name, q_type):
        self.lock.acquire()

        self.buffer[q_name].pop(q_type)
        if len(self.buffer[q_name]) == 0:
            self.buffer.pop(q_name)

        self.lock.release()

    # Проверка записей на истечение времени храненияв кэше
    def _is_late_records(self, q_name, q_type) -> bool:
        t, records = self.buffer[q_name][q_type]
        dt = (datetime.now() - t).seconds
        print(dt)
        for record in records:
            print(record.r_ttl)
            if dt >= record.r_ttl:
                return True
        return False

    # Сохраняем все данные из буффера в файл
    def save(self):
        pickle.dump(
            self.buffer, open(self.path, "wb"), protocol=pickle.HIGHEST_PROTOCOL
        )

    # Закрываем кэш
    def close(self):
        self.cleaner.join(1)