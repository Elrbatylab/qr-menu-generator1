bind = "0.0.0.0:10000"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
timeout = 120
keepalive = 5
max_requests = 100
worker_class = 'sync'
reload = True
