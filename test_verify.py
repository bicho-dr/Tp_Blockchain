from common import *

ca = load_ca_cert()

for name in PEERS:
    ok, why = verify_certificate(load_cert(name), ca)
    print(f"{name:6} -> {ok} ({why})")

# اختبار سلبي: شهادة الـ CA نفسها ليست شهادة عقدة من الـ CA، ولا تمر بنفس الفحص
ok, why = verify_certificate(ca, ca)
print("CA as node ->", ok, f"({why})")