from etw_analyzer.native.worker_supervisor import run_csharp_worker_extraction
from etw_analyzer.native import cache as native_cache
from etw_analyzer.native.config import find_csharp_sidecar
from pathlib import Path
import time

etl = Path(r'C:\git\wpr-mcp-poc-staging\real-fixture\spike-fixture.etl')
export_dir = Path(r'C:\Temp\etw-export-csharp-smoke')

print('SIDECAR_PATH=' + str(find_csharp_sidecar()))
print('ETL_SIZE_MB=' + str(etl.stat().st_size / (1024*1024)))

start = time.monotonic()
r = run_csharp_worker_extraction(
    etl_path=etl,
    export_dir=export_dir,
    trace_id='trace_smoke_csharp',
    symbol_path=None,
    requested_event_classes=[
        'SampledProfile', 'CSwitch',
        'TcpIp/Recv', 'UdpIp/Recv',
        'AFD/Recv', 'NdisDrop',
        'HttpService/Recv', 'Quic/PacketRecv',
    ],
)
elapsed = time.monotonic() - start
print('OK=' + str(r.ok))
print('MSG=' + r.message)
print('WALL_E2E_S=' + str(round(elapsed, 2)))

if r.result:
    perf = r.result.get('performance', {})
    ec = r.result.get('event_counts', {})
    print('SIDECAR_WALL_S=' + str(perf.get('wall_seconds')))
    print('SIDECAR_EPS=' + str(perf.get('events_per_second')))
    print('SIDECAR_PEAK_RSS_MB=' + str(perf.get('peak_rss_mb')))
    print('EVENT_SAMPLED=' + str(ec.get('SampledProfile')))
    print('EVENT_CSWITCH=' + str(ec.get('CSwitch')))

m = native_cache.read_manifest(export_dir)
if m:
    print('MANIFEST_PRODUCER=' + m.producer)
    print('MANIFEST_SCHEMA=' + str(m.schema_version))
    print('MANIFEST_DATASETS=' + str(len(m.datasets)))
    names = sorted({d.name for d in m.datasets})
    print('MANIFEST_DATASET_NAMES=' + ','.join(names[:40]))
