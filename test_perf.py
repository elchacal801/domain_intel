import stix2
import time
import uuid

print("Generating 100k indicators...")
start = time.time()
inds = []
for i in range(100000):
    ind = stix2.Indicator(
        id=f"indicator--{uuid.uuid4()}",
        pattern=f"[domain-name:value = 'test{i}.com']",
        pattern_type="stix",
        valid_from="2026-01-01T00:00:00Z",
        allow_custom=True
    )
    inds.append(ind)
    if i > 0 and i % 10000 == 0:
        print(f"Generated {i} in {time.time()-start:.2f}s")
        start = time.time()

print("Building bundle...")
start = time.time()
b = stix2.Bundle(objects=inds, allow_custom=True)
print(f"Bundle built in {time.time()-start:.2f}s")

print("Serializing...")
start = time.time()
s = b.serialize()
print(f"Serialized in {time.time()-start:.2f}s")

print("Parsing (validation)...")
start = time.time()
stix2.parse(s, allow_custom=True)
print(f"Parsed in {time.time()-start:.2f}s")
