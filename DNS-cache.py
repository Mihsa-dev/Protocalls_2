import socket
import struct
import time
import threading
import pickle
import os
from collections import defaultdict


class DNSCache:
    def __init__(self):
        self.domain_to_records = defaultdict(list)
        self.ip_to_domain = defaultdict(list)
        self.expiration_times = {}

    def add_record(self, name, rtype, data, ttl):
        key = (name.lower(), rtype, data.lower())
        expiration = time.time() + ttl
        self.expiration_times[key] = expiration

        if rtype in ('A', 'AAAA'):
            self.domain_to_records[(name.lower(), rtype)].append((data, expiration))
            self.ip_to_domain[(data.lower(), 'PTR')].append((name.lower(), expiration))
        elif rtype in ('NS', 'PTR'):
            self.domain_to_records[(name.lower(), rtype)].append((data.lower(), expiration))

    def get_records(self, name, rtype):
        name = name.lower()
        current_time = time.time()
        records = []

        for data, expiration in self.domain_to_records.get((name, rtype), []):
            if expiration > current_time:
                records.append(data)

        return records if records else None

    def cleanup_expired(self):
        current_time = time.time()
        expired_keys = [k for k, exp in self.expiration_times.items() if exp <= current_time]

        for key in expired_keys:
            name, rtype, data = key
            # Удаляем из domain_to_records
            if (name, rtype) in self.domain_to_records:
                self.domain_to_records[(name, rtype)] = [
                    (d, e) for d, e in self.domain_to_records[(name, rtype)]
                    if d != data or e > current_time
                ]
                if not self.domain_to_records[(name, rtype)]:
                    del self.domain_to_records[(name, rtype)]

            # Удаляем из ip_to_domain (для A/AAAA записей)
            if rtype in ('A', 'AAAA'):
                if (data, 'PTR') in self.ip_to_domain:
                    self.ip_to_domain[(data, 'PTR')] = [
                        (d, e) for d, e in self.ip_to_domain[(data, 'PTR')]
                        if d != name or e > current_time
                    ]
                    if not self.ip_to_domain[(data, 'PTR')]:
                        del self.ip_to_domain[(data, 'PTR')]

            del self.expiration_times[key]

    def save_to_file(self, filename):
        data = {
            'domain_to_records': dict(self.domain_to_records),
            'ip_to_domain': dict(self.ip_to_domain),
            'expiration_times': self.expiration_times
        }
        with open(filename, 'wb') as f:
            pickle.dump(data, f)

    @classmethod
    def load_from_file(cls, filename):
        if not os.path.exists(filename):
            return cls()

        with open(filename, 'rb') as f:
            data = pickle.load(f)

        cache = cls()
        cache.domain_to_records.update(data['domain_to_records'])
        cache.ip_to_domain.update(data['ip_to_domain'])
        cache.expiration_times.update(data['expiration_times'])

        # Очищаем просроченные записи при загрузке
        cache.cleanup_expired()
        return cache


class DNSServer:
    def __init__(self, cache_file='dns_cache.pkl'):
        self.cache_file = cache_file
        self.cache = DNSCache.load_from_file(cache_file)
        self.cleanup_thread = threading.Thread(target=self.periodic_cleanup, daemon=True)
        self.running = False
        self.root_servers = [
            '198.41.0.4',  # a.root-servers.net
            '199.9.14.201',  # b.root-servers.net
            '192.33.4.12',  # c.root-servers.net
            '199.7.91.13',  # d.root-servers.net
            '192.203.230.10',  # e.root-servers.net
            '192.5.5.241',  # f.root-servers.net
            '192.112.36.4',  # g.root-servers.net
            '198.97.190.53',  # h.root-servers.net
            '192.36.148.17',  # i.root-servers.net
            '192.58.128.30',  # j.root-servers.net
            '193.0.14.129',  # k.root-servers.net
            '199.7.83.42',  # l.root-servers.net
            '202.12.27.33'  # m.root-servers.net
        ]

    def start(self):
        self.running = True
        self.cleanup_thread.start()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('0.0.0.0', 53))
                print("DNS server started on port 53")

                while self.running:
                    try:
                        data, addr = sock.recvfrom(512)
                        threading.Thread(target=self.handle_request, args=(sock, data, addr)).start()
                    except Exception as e:
                        print(f"Error handling request: {e}")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        self.cache.save_to_file(self.cache_file)
        print("DNS server stopped")

    def periodic_cleanup(self):
        while self.running:
            time.sleep(60)  # Проверка каждую минуту
            self.cache.cleanup_expired()

    def handle_request(self, sock, data, addr):
        try:
            # Парсим запрос
            transaction_id = data[:2]
            query = data[12:]

            # Извлекаем запрашиваемое имя и тип
            name_parts = []
            pos = 0
            while True:
                length = query[pos]
                if length == 0:
                    break
                name_parts.append(query[pos + 1:pos + 1 + length].decode('ascii'))
                pos += 1 + length
            qname = '.'.join(name_parts)
            pos += 1  # Пропускаем нулевой байт

            qtype = struct.unpack('!H', query[pos:pos + 2])[0]

            # Проверяем кэш
            cached_response = self.check_cache(qname, qtype)
            if cached_response:
                response = transaction_id + b'\x80\x00'  # Флаги: QR=1, Recursion Available=1
                response += b'\x00\x01'  # 1 вопрос
                response += struct.pack('!H', 1)  # 1 ответ (из кэша)
                response += b'\x00\x00\x00\x00'  # No authority or additional records
                response += query  # Вопрос
                response += cached_response  # Ответ из кэша
                sock.sendto(response, addr)
                return

            # Если нет в кэше, выполняем рекурсивный запрос
            response = self.recursive_resolve(qname, qtype)
            if response:
                # Формируем полный ответ
                full_response = transaction_id + b'\x80\x00'  # Флаги: QR=1, Recursion Available=1
                full_response += b'\x00\x01'  # 1 вопрос
                full_response += struct.pack('!H', len(response) // 16)  # Количество ответов
                full_response += b'\x00\x00\x00\x00'  # No authority or additional records
                full_response += query  # Вопрос
                full_response += response  # Ответ
                sock.sendto(full_response, addr)
            else:
                # Отправляем ошибку
                error_response = transaction_id + b'\x80\x00'  # Флаги: QR=1, Recursion Available=1
                error_response += b'\x00\x01\x00\x00\x00\x00\x00\x00'  # 1 вопрос, 0 ответов
                error_response += query  # Вопрос
                sock.sendto(error_response, addr)
        except Exception as e:
            print(f"Error processing request: {e}")

    def check_cache(self, qname, qtype):
        type_str = self.type_to_str(qtype)
        if not type_str:
            return None

        records = self.cache.get_records(qname, type_str)
        if not records:
            return None

        response = b''
        for record in records:
            if type_str in ('A', 'AAAA'):
                # Для A/AAAA записей
                response += b'\xc0\x0c'  # Указатель на имя в вопросе
                response += struct.pack('!H', qtype)
                response += b'\x00\x01'  # Класс IN
                response += struct.pack('!I', 300)  # TTL (5 минут)
                if type_str == 'A':
                    response += b'\x00\x04'  # Длина данных (IPv4)
                    response += socket.inet_aton(record)
                else:
                    response += b'\x00\x10'  # Длина данных (IPv6)
                    response += socket.inet_pton(socket.AF_INET6, record)
            elif type_str in ('NS', 'PTR'):
                # Для NS/PTR записей
                encoded_name = self.encode_dns_name(record)
                response += b'\xc0\x0c'  # Указатель на имя в вопросе
                response += struct.pack('!H', qtype)
                response += b'\x00\x01'  # Класс IN
                response += struct.pack('!I', 300)  # TTL (5 минут)
                response += struct.pack('!H', len(encoded_name))
                response += encoded_name

        return response

    def recursive_resolve(self, qname, qtype, depth=0):
        if depth > 10:  # Предотвращаем бесконечную рекурсию
            return None

        type_str = self.type_to_str(qtype)
        if not type_str:
            return None

        # Пробуем начать с корневых серверов
        nameservers = self.root_servers.copy()
        last_resort_servers = self.root_servers.copy()

        while nameservers:
            ns = nameservers.pop(0)
            try:
                response = self.send_dns_query(qname, qtype, ns)
                if not response:
                    continue

                # Парсим ответ
                answers, authority, additional = self.parse_dns_response(response)

                # Добавляем все записи в кэш
                self.add_to_cache(answers + authority + additional)

                # Ищем ответ на наш запрос
                for answer in answers:
                    if answer[1] == qtype:
                        return self.build_answer_section([answer])

                # Если есть CNAME, следуем по нему
                cname = None
                for answer in answers:
                    if answer[1] == 5:  # CNAME
                        cname = answer[3]
                        break

                if cname:
                    return self.recursive_resolve(cname, qtype, depth + 1)

                # Ищем новые nameservers в additional
                new_ns = []
                for rr in additional:
                    if rr[1] == 1:  # A запись
                        new_ns.append(rr[3])

                # Если не нашли в additional, ищем NS в authority и рекурсивно разрешаем их
                if not new_ns:
                    for rr in authority:
                        if rr[1] == 2:  # NS запись
                            ns_name = rr[3]
                            ns_ip = self.recursive_resolve(ns_name, 1)  # Рекурсивно разрешаем A запись
                            if ns_ip:
                                new_ns.append(ns_ip)

                if new_ns:
                    nameservers = new_ns + nameservers
                    last_resort_servers = new_ns + last_resort_servers

            except Exception as e:
                print(f"Error querying {ns} for {qname}: {e}")
                continue

        return None

    def send_dns_query(self, qname, qtype, server, timeout=3):
        query = self.build_dns_query(qname, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (server, 53))
            try:
                data, _ = sock.recvfrom(512)
                return data
            except socket.timeout:
                return None
            except Exception as e:
                print(f"Error receiving from {server}: {e}")
                return None

    def build_dns_query(self, qname, qtype):
        transaction_id = os.urandom(2)
        flags = b'\x01\x00'  # Рекурсивный запрос
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'

        header = transaction_id + flags + questions + answers + authority + additional
        question = self.encode_dns_name(qname) + struct.pack('!HH', qtype, 1)  # Класс IN

        return header + question

    def parse_dns_response(self, data):
        pos = 12  # Пропускаем заголовок

        # Пропускаем вопросы
        qdcount = struct.unpack('!H', data[4:6])[0]
        for _ in range(qdcount):
            while data[pos] != 0:
                pos += 1
            pos += 5  # Пропускаем нулевой байт и QTYPE/QCLASS

        answers = []
        ancount = struct.unpack('!H', data[6:8])[0]
        for _ in range(ancount):
            name, pos = self.decode_dns_name(data, pos)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            pos += rdlength

            if rtype == 1:  # A запись
                ip = socket.inet_ntoa(rdata)
                answers.append((name, rtype, ttl, ip))
            elif rtype == 28:  # AAAA запись
                ip = socket.inet_ntop(socket.AF_INET6, rdata)
                answers.append((name, rtype, ttl, ip))
            elif rtype == 2:  # NS запись
                ns_name, _ = self.decode_dns_name(data, pos)
                answers.append((name, rtype, ttl, ns_name))
            elif rtype == 12:  # PTR запись
                ptr_name, _ = self.decode_dns_name(data, pos)
                answers.append((name, rtype, ttl, ptr_name))
            elif rtype == 5:  # CNAME запись
                cname, _ = self.decode_dns_name(data, pos)
                answers.append((name, rtype, ttl, cname))

        authority = []
        nscount = struct.unpack('!H', data[8:10])[0]
        for _ in range(nscount):
            name, pos = self.decode_dns_name(data, pos)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            pos += rdlength

            if rtype == 2:  # NS запись
                ns_name, _ = self.decode_dns_name(data, pos)
                authority.append((name, rtype, ttl, ns_name))

        additional = []
        arcount = struct.unpack('!H', data[10:12])[0]
        for _ in range(arcount):
            name, pos = self.decode_dns_name(data, pos)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            pos += rdlength

            if rtype == 1:  # A запись
                ip = socket.inet_ntoa(rdata)
                additional.append((name, rtype, ttl, ip))
            elif rtype == 28:  # AAAA запись
                ip = socket.inet_ntop(socket.AF_INET6, rdata)
                additional.append((name, rtype, ttl, ip))

        return answers, authority, additional

    def add_to_cache(self, records):
        for name, rtype, ttl, data in records:
            type_str = self.type_to_str(rtype)
            if type_str:
                self.cache.add_record(name, type_str, data, ttl)

    def build_answer_section(self, answers):
        response = b''
        for name, rtype, ttl, data in answers:
            response += b'\xc0\x0c'  # Указатель на имя в вопросе
            response += struct.pack('!H', rtype)
            response += b'\x00\x01'  # Класс IN
            response += struct.pack('!I', ttl)

            if rtype == 1:  # A запись
                response += b'\x00\x04'  # Длина данных
                response += socket.inet_aton(data)
            elif rtype == 28:  # AAAA запись
                response += b'\x00\x10'  # Длина данных
                response += socket.inet_pton(socket.AF_INET6, data)
            elif rtype in (2, 5, 12):  # NS, CNAME, PTR
                encoded_name = self.encode_dns_name(data)
                response += struct.pack('!H', len(encoded_name))
                response += encoded_name

        return response

    def encode_dns_name(self, name):
        encoded = b''
        for part in name.split('.'):
            encoded += bytes([len(part)]) + part.encode('ascii')
        return encoded + b'\x00'

    def decode_dns_name(self, data, pos):
        name = []
        while True:
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xc0 == 0xc0:  # Указатель
                pointer = struct.unpack('!H', data[pos:pos + 2])[0] & 0x3fff
                part, _ = self.decode_dns_name(data, pointer)
                name.append(part)
                pos += 2
                break
            else:
                pos += 1
                name.append(data[pos:pos + length].decode('ascii'))
                pos += length
        return '.'.join(name), pos

    def type_to_str(self, qtype):
        return {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            12: 'PTR',
            28: 'AAAA'
        }.get(qtype)


if __name__ == '__main__':
    server = DNSServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()