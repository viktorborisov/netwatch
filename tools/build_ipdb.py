#!/usr/bin/env python3
"""
build_ipdb.py — собирает компактную IP->страна+координаты базу из
GeoLite2 city CSV (npm-пакет @ip-location-db/geolite2-city).

Зачем: полная city-база это ~2.5M диапазонов и ~466MB RSS при наивном
подходе (список кортежей) — это OOM на VPS с 868MB. Для КАРТЫ город не
нужен, достаточно страны + одной средней точки на страну.

Алгоритм в ДВА прохода, чтобы не держать 2.5M записей в памяти:
  проход 1: собрать страны и их средние координаты (память ~250 стран)
  проход 2: писать диапазоны сразу в файл (память O(1))

Исходный GeoLite2 CSV отсортирован по start_ip (проверяется на лету);
если нет — предупреждаем и всё равно пишем как есть.

Формат ipdb.bin:
  [4 байта] длина JSON-заголовка (big-endian uint32)
  [JSON]    {"count": N, "countries": [{"cc":"RU","lat":..,"lon":..}, ...]}
  [двоичные записи] N × (start:uint32, end:uint32, cc_idx:uint16)  big-endian

Использование:
  python3 build_ipdb.py geolite2-city-ipv4-num.csv.gz ipdb.bin
"""
import sys
import gzip
import json
import struct


def opener(path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace")


def iter_rows(path):
    """Отдаёт (start_int, end_int, cc, lat, lon) по одной строке."""
    with opener(path) as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) < 10:
                continue
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                continue
            cc = parts[2].strip()
            if not cc:
                continue
            lat_s, lon_s = parts[7], parts[8]
            if not lat_s or not lon_s:
                continue
            try:
                lat = float(lat_s)
                lon = float(lon_s)
            except ValueError:
                continue
            yield start, end, cc, lat, lon


def main():
    if len(sys.argv) != 3:
        print("usage: build_ipdb.py <input.csv[.gz]> <output.bin>")
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]

    # ---- проход 1: для каждой страны ищем самый частый "город" ----
    # Средние координаты по стране плохо годятся (РФ усредняется в
    # Поволжье). Берём моду по округлённым до 0.1 координатам — это
    # реальный крупный город/точка концентрации диапазонов страны.
    from collections import Counter
    counters = {}   # cc -> Counter((lat10, lon10) -> freq)
    for _s, _e, cc, lat, lon in iter_rows(src):
        # взвешиваем по ширине диапазона: крупные сети важнее мелких
        w = _e - _s + 1
        key = (round(lat, 1), round(lon, 1))
        c = counters.get(cc)
        if c is None:
            counters[cc] = {key: w}
        else:
            c[key] = c.get(key, 0) + w

    countries = []
    cc_index = {}
    for cc, c in counters.items():
        (lat10, lon10), _freq = max(c.items(), key=lambda kv: kv[1])
        cc_index[cc] = len(countries)
        countries.append({"cc": cc, "lat": lat10, "lon": lon10})

    # ---- проход 2: потоковая запись диапазонов ----
    count = 0
    prev_start = -1
    unsorted = False
    with open(dst, "wb") as out:
        # заголовок пишем после, а пока оставим место под 4 байта длины.
        # Проще: собрать диапазоны нельзя (память), поэтому пишем
        # "count" и заголовок в отдельный временный хвост. Вместо этого
        # используем фокус: пишем данные в отдельный файл, затем склеиваем.
        data_tmp = dst + ".data"
        with open(data_tmp, "wb") as d:
            for start, end, cc, _lat, _lon in iter_rows(src):
                if start < prev_start and not unsorted:
                    unsorted = True
                prev_start = start
                d.write(struct.pack(">IIH", start, end, cc_index[cc]))
                count += 1

        header = json.dumps({"count": count, "countries": countries},
                            separators=(",", ":")).encode("utf-8")
        out.write(struct.pack(">I", len(header)))
        out.write(header)
        # дописываем данные из временного файла кусками
        with open(data_tmp, "rb") as d:
            while True:
                chunk = d.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
    import os
    os.remove(data_tmp)

    if unsorted:
        print("WARNING: входной файл НЕ отсортирован по start_ip",
              file=sys.stderr)
    print(f"wrote {dst}: {count} ranges, {len(countries)} countries, "
          f"header {len(header)} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
