import os, time, json

def get_pkt_counter(entry):
    x = os.popen('nikss-ctl table get pipe 1 ingress_tbl_fwd').read()
    x = json.loads(x)
    return int(x['ingress_tbl_fwd']['entries'][entry]['DirectCounter']['ingress_forward_counter']['packets'], 16)

t0, dt = 0, 0
c0, dc = 0, 0

while (1):
    t0 = time.time()
    c0 = get_pkt_counter(2)
    time.sleep(1)
    dt = time.time() - t0
    dc = get_pkt_counter(2) - c0
    print(dc/dt)