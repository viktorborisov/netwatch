"""
ipdb.py — чтение компактной базы IP->страна+координаты (ipdb.bin).

Формат файла (см. tools/build_ipdb.py):
  [4 байта] длина JSON-заголовка (big-endian uint32)
  [JSON]    {"count": N, "countries": [{"cc":"RU","lat":..,"lon":..}, ...]}
  [N записей] start:uint32, end:uint32, cc_idx:uint16  (big-endian)

Диапазоны отсортированы по start (GeoLite2 идёт по возрастанию),
поэтому поиск — бинарный (bisect) по массиву start.

Память: держим start/end/idx как array('I')/array('H'). Для 2.56M
записей это ~4+4+2 = ~25MB. Приемлемо для контейнера с лимитом 128M.
Для экономии можно поднять лимит, но и так влезает.
"""
import struct
import json
from array import array


class IPDB:
    def __init__(self, path):
        self.path = path
        self.starts = array("I")   # беззнаковые 32-бит
        self.ends = array("I")
        self.idx = array("H")      # индекс страны, 250 стран -> хватает uint16
        self.countries = []
        self.count = 0
        self._load(path)

    def _load(self, path):
        with open(path, "rb") as f:
            (hlen,) = struct.unpack(">I", f.read(4))
            header = json.loads(f.read(hlen))
            self.count = header["count"]
            self.countries = header["countries"]
            # заранее резервируем ровно count элементов
            self.starts = array("I")
            self.ends = array("I")
            self.idx = array("H")
            rec = struct.Struct(">IIH")
            # читаем блоками, чтобы не плодить мусор
            block = 1 << 20
            buf = f.read(rec.size * min(block, self.count))
            while buf:
                n = len(buf) // rec.size
                for i in range(n):
                    s, e, c = rec.unpack_from(buf, i * rec.size)
                    self.starts.append(s)
                    self.ends.append(e)
                    self.idx.append(c)
                buf = f.read(rec.size * block)

    def lookup(self, ip_str):
        """Возвращает dict {cc, lat, lon} или None, если не найдено."""
        n = _ip_to_int(ip_str)
        if n is None:
            return None
        # бинарный поиск по starts
        lo, hi = 0, len(self.starts) - 1
        pos = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.starts[mid] <= n:
                pos = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if pos is None:
            return None
        if self.starts[pos] <= n <= self.ends[pos]:
            return self.countries[self.idx[pos]]
        return None


def _ip_to_int(s):
    """IPv4 строку -> uint32. IPv6 и мусор -> None (мы храним только v4)."""
    if not s or ":" in s:
        return None
    parts = s.split(".")
    if len(parts) != 4:
        return None
    try:
        a, b, c, d = (int(x) for x in parts)
    except ValueError:
        return None
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        return None
    return (a << 24) | (b << 16) | (c << 8) | d


if __name__ == "__main__":
    import sys
    db = IPDB(sys.argv[1] if len(sys.argv) > 1 else "ipdb.bin")
    print(f"loaded {db.count} ranges, {len(db.countries)} countries")
    tests = ["1.1.1.1", "8.8.8.8", "77.88.55.66", "194.87.239.102",
             "142.250.185.78", "185.199.108.153", "не-ip"]
    for t in tests:
        print(f"  {t:20} -> {db.lookup(t)}")
