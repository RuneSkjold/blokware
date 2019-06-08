'''
blokware community server
Copyright 2016 Jonas Helguson <jonas@husblok.net>
You may use, modify and/or redistribute this program under the
terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License,
or (at your option) any later version; for details see the GNU
Affero General Public License at http://www.gnu.org/licenses/

*******************************************************************
 REQUIREMENTS AND INSTALLATION INSTRUCTIONS
*******************************************************************

Dependencies:

* Python 3
* A web server with Python (WSGI) support
* MongoDB and the python bindings for it (pymongo)
* The pycrypto [or pycryptodome?] python module
* The bcrypt python module
* (also, TinyMCE for HTML editing, but it's loaded from their CDN)

You can verify that the necessary python modules are installed
correctly by launching a python3 shell and running the following line:
import pymongo,bson,bcrypt,Crypto

To install, mount blokware.wsgi on / and map the path /blokware/ to
the blokware directory. Then visit https://yourhostname/blokwaresetup
in a browser.

*******************************************************************
 QUICK SETUP ON DEBIAN OR A DEBIAN-DERIVED SYSTEM SUCH AS UBUNTU
*******************************************************************

Here are quick instructions to get blokware running on a Debian-based
system, using the Apache web server, encrypted with the Let's Encrypt
tool. Do NOT use these instructions if you are already running Apache,
as they will destroy/overwrite your existing web site configuration.

* Run the following three commands as root:

apt-get install apache2 certbot libapache2-mod-wsgi-py3 mongodb python3-pymongo python3-crypto python3-bcrypt

certbot --apache --redirect

???Nødvendig???   rm /etc/apache2/sites-available/default-ssl.conf && 
sed "N;N;s/DocumentRoot \/var\/www\/html\n\n/DocumentRoot \/var\/www\/html\nWSGIScriptAlias \/ \/var\/www\/blokware\/blokware.wsgi\nAlias \/blokware \/var\/www\/blokware\n\n/g" /etc/apache2/sites-available/000-default-le-ssl.conf > /tmp/000-default-le-ssl.conf && cp /tmp/000-default-le-ssl.conf /etc/apache2/sites-available
XXX burde bruge den anden modwsgi-mode

* Extract the blokware archive to the /var/www/ directory, and then
  visit https://yourhostname/blokwaresetup in a browser.

*******************************************************************
 ASSUMPTIONS AND NON-STANDARD USE CASES
*******************************************************************

As written, this software currently assumes that you want to do
both of the following:
1) run it over HTTPS
2) either run several separate setups (databases) on the same server,
  distinguished by the HTTP Host header used to access them, or run
  only one setup and only access it using one hostname.

In case those assumptions aren't true for your use case, you need to
change the code as follows:

1) If you want to run blokware over unencrypted HTTP, you need to
remove the word |Secure;| where the login cookie is set, and if you
want notifications to work, change |https| to |http| a couple of
places where a full URL is generated.

2) If you want to access a single blokware database using more than one
Host header for some reason, you need to change the line that sets
|dbname| to hardcode it to whatever your database is called.

*******************************************************************

Written in the Nike style of programming ("just do it").

'''

#FIXME find_one_and_[...] bruges flere steder hvor returndocument ikke bruges - burde vaere [...]_one

import hashlib, string
import gettext, locale
from datetime import datetime, timedelta
import pymongo, bson.errors
from bson.objectid import ObjectId
import bcrypt
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import new as RSApadding
from Crypto import Random
from Crypto.Random import random

LOGIN_SCREEN_IMAGES = {#by default, /blokware/siteimages/[host].cover.png is used. you can override here for
                       #individual hosts; you can specify multiple images and they'll shuffle. for example:
                       'houseblock.example.net':       ['/something/foo.png', '/coverpics/a.png', '/coverpics/b.jpg'],
                       'test.husblok.net':             ['/blokware/siteimages/0', '/blokware/siteimages/1', '/blokware/siteimages/2'],
                       'meta.husblok.net':             ['/blokware/siteimages/0', '/blokware/siteimages/1', '/blokware/siteimages/2'],
                       'ontologiskanarki.husblok.net': ['/blokware/siteimages/0', '/blokware/siteimages/1', '/blokware/siteimages/2'],
                       'trythisone.example':           ['''"><script>var nasa_apod = new XMLHttpRequest(); nasa_apod.addEventListener("load", function(){document.querySelector("img").src=(this.responseText.split('"').slice(-2,-1))}); nasa_apod.open("GET", "https://api.nasa.gov/planetary/apod?api_key=DEMO_KEY"); nasa_apod.send(); document.querySelector("img").style.maxHeight="420px"</script><br dummy="'''],
                      }
LANGUAGES = ['da','en','fr','ma']
SKINS = ['original','narrow','narrow-red','narrow-red-thread','dark','tilt','hungover','mirror','c64']
MAXLEN = {'title': 256}
DBPREFIX = 'blokw_'

_TRUSTED_SERVERS = {'meta.husblok.net', 'dagmarsminde.husblok.net', 'ontologiskanarki.husblok.net'}

def application(env, start_response):
    import cgi

    post_env = env.copy()
    post_env['QUERY_STRING'] = ''
    post = cgi.FieldStorage(fp=post_env['wsgi.input'], environ=post_env, keep_blank_values=True)
    qs = {}
    for piece in env['QUERY_STRING'].split('&'):
        piece = piece.split('=', 1)
        qs[piece[0]] = piece[len(piece) - 1]

    dbc = pymongo.MongoClient()    

    if env['PATH_INFO'] == '/blokwaresetup':
        start_response('404 Not Found', [('Cache-Control', 'no-store'), ('Content-Type', 'text/html; charset=utf-8')])
        masterconfigdb = dbc['blokware_config']
        serveradminconfig = masterconfigdb.serveradmin.find_one()
        
        if serveradminconfig and 'password' not in post:
            return [b'<form method=post>Password: <input name=password type=password><br><br><input type=submit value="Continue"></form>']
        elif serveradminconfig and post['password'].value != serveradminconfig['password']:
            return [b'']
        elif 'updatecert' in post:
            dblist = [(' -d ' + dbn[len(DBPREFIX):].replace('_', '.')).encode() if dbn.startswith(DBPREFIX) else b'' for dbn in dbc.database_names()]
            return [b'If you are using apache and letsencrypt, run the following command to update letsencrypt&apos;s certificate to include all your host names:<br><br><code>certbot certonly --expand --apache --non-interactive '] + dblist
        elif 'hostname' in post:
            newdb = dbc[DBPREFIX + post['hostname'].value.replace('.', '_')]
            if newdb.people.find_one():
                return [b'The database already exists and has at least one user account -- something wrong?']
            create_user(newdb, post['username'].value, '', level=-1)
            newdb.config.insert_one({'frontpage': 'events', 'default_language': 'en', 'emailout':{'smtpserver':'','mailfrom':''}})

            def reslink(res): return b'<code><a target="_blank" href="' + get_resource_path(res, post['hostname'].value).encode() + b'">' + get_resource_path(res, post['hostname'].value).encode() + b'</a></code>'
            msg = b'Database created.<br><br>Place the icon that you want to be displayed for this site at ' + reslink('icon') + b' and the image that you want displayed on the login screen at ' + reslink('cover') + b'.'
            if serveradminconfig:
                return [msg + b'<br><br><form method=post><input type=hidden name=password value="' + esc(serveradminconfig['password']).encode() + b'"><input type=hidden name=updatecert value=1><input type=submit value="Update letsencrypt certificate..."></form>']
            else:
                masterconfigdb.serveradmin.insert_one({'password': post['desiredpassword'].value})
                return [msg + b'<br><br>You can now <a href="/changepassword">log in</a> with the user name <code>' + esc(post['username'].value).encode() + b'</code>']
        else:
            output = []
            if serveradminconfig:
                output += [b'<h1>Existing databases</h1><p>These are the databases that exist at the moment:</p>']
                output += [b'' if not dbn.startswith(DBPREFIX) else dbn.encode() + b'<br>' for dbn in dbc.database_names()]
                output += [b'<br><hr>']
            output += [b'<h1>New database creation</h1><form method=post>']
            if serveradminconfig:
                output += [b'<input type=hidden name=password value="' + esc(serveradminconfig['password']).encode() + b'">']
                hostnamefieldparams = b''
            else:
                output += [b'Password to create more databases in the future:<br><input required name=desiredpassword><br><br>']
                hostnamefieldparams = b'readonly value="' + env['HTTP_HOST'].encode() + b'"'
            output += [b'Hostname to access this database: (e.g. houseblock.example.org)<br><input required ', hostnamefieldparams, b' name=hostname><br><br>Name of first user account:<br><input required name=username><br><br>Confirm above values are correct:<br><input type=checkbox onchange="document.getElementById(\'createbutton\').disabled=!this.checked"><br><br><input id=createbutton disabled type=submit value="Create database"></form>']
            if serveradminconfig:
                output += [b'<hr><h1>Encryption certificate update</h1><form method=post><input type=hidden name=password value="' + esc(serveradminconfig['password']).encode() + b'"><input type=hidden name=updatecert value=1><input type=submit value="Update letsencrypt certificate..."></form><br>']
            return output

    response_status = '200 OK'
    response_headers = [('Content-Type', 'text/html; charset=utf-8')]
    output = []
    pagetitle = ''
    include_html_header = True

    dbname = DBPREFIX + env['HTTP_HOST'].replace('.', '_')
    if not dbname in dbc.database_names():
        start_response('404 Not Found', response_headers)
        return [b'<title>404 Not Found</title><h1>Not Found</h1><p>There is nothing at this address.</p>']
    db = dbc[dbname]
    config = db.config.find_one()
    
    user = None
    if 'HTTP_COOKIE' in env:
        cookie = env['HTTP_COOKIE'].split('=')
        if cookie[0] != 'blokwarelogin' or len(cookie) != 4 or cookie[3] != '':
            output = ['<h1>Bad cookie format</h1>' + repr(env['HTTP_COOKIE'])]
        else:
            login = db.logins.find_one({'token': cookie[1]})
            if login:
                user = db.people.find_one(login['userid'])
                prvkey_passphrase = cookie[2]

    set_language(env, user['pref_language'] if user and 'pref_language' in user else config['default_language'])

    path = env['PATH_INFO'].split('/')[1:]
    if path == ['']:
        path = [config['frontpage']]
        if user and len(env['QUERY_STRING']) > 42 and env['QUERY_STRING'][:10] == "EVILEMPIRE":
            user['evilempireid'] = env['QUERY_STRING'][10:]
            db.people.replace_one({'_id': user['_id']}, user)

    if path[0] == 'logout':
        if user:
            if 'Android' in env['HTTP_USER_AGENT']:
                db.people.find_one_and_update({'_id': user['_id']}, {'$unset': {'evilempireid':''}})
            db.logins.delete_many({'userid':user['_id']})
        response_headers += [('set-cookie', 'blokwarelogin=; Max-Age=0; HttpOnly; Secure; Path=/;')]
        response_headers += [('location', '/')]
        response_status = '303 Goodbye'
        include_html_header = False
        output = ['<h1><a href="/">Log in</a></h1>']

    elif path == ['blokware.webmanifest']:
        response_headers = [('Content-Type', 'application/manifest+json; charset=utf-8')]
        include_html_header = False
        output = ['{"name": "' + env['HTTP_HOST'].split('.')[0].title() + '","start_url": "/","display": "standalone","orientation": "any","icons": [{"sizes": "144x144", "src":"' + get_resource_path('icon', env['HTTP_HOST']) + '"}]}']
    
    elif path == ['_NOTIFY_PING']:
        include_html_header = False
        output = ['foo']
        release_carrier_pidgeons(env, db, config['emailout'])

    elif path == ['_v0msgsync_init'] and qs['s'] in _TRUSTED_SERVERS: #...and method = POST, for good measure
        include_html_header = False
        result = http_request(qs['s'], '/_v0msgsync_fetch?k=' + qs['k'])
        if result[0] == 200:
            #er det her vi skal checke om brugeren findes i vores alien_friends? er det her vi skal smide den ind? eller afvise hvis ikke?
            to_name, from_name, key_len, msg_len, key_and_msg = result[1].split(b'\n', 4)
            assert len(key_and_msg) == int(key_len.decode()) + int(msg_len.decode())
            to_user = db.people.find_one({'name': to_name.decode()})
            db.messages.insert_one({'to': to_user['_id'], 'from': from_name.decode() + '@' + qs['s'].replace('.', '_'), 'keys': {str(to_user['_id']): key_and_msg[:int(key_len.decode())]}, 'msg': key_and_msg[int(key_len.decode()):]})

    elif path == ['_v0msgsync_fetch']: #...and method = POST, for good measure
        include_html_header = False
        msg = db.messages_outgoing.find_one({'idkey': qs['k']})
        if msg:
            start_response('200 OK', [('Content-Type', 'application/octet-stream')])
            msg = db.messages.find_one(msg['_id'])
            rcpt_key = msg['keys'][msg['to']]
            names = msg['to'].split('@')[0].encode() + b'\n' + dbcacheget(db, 'people', msg['from'], ['name'])['name'].encode()
            return [names, b'\n', str(len(rcpt_key)).encode(), b'\n', str(len(msg['msg'])).encode(), b'\n', rcpt_key, msg['msg']]

    elif path[0] == '_v0insecurekeyexchange' and path[1] in _TRUSTED_SERVERS:
        id=db.v0keyexchangetodo.insert_one({'remoteserver':path[1],'remoteuser':path[2],'localuser':user['_id']}).inserted_id
        http_request(path[1], '/_v0insecurekeyexchangeB/' + env['HTTP_HOST'] + '/' + path[2] + '/' + str(id) + '/' + urlesc(user['name'])) #server, ownuser, token, myuser
        include_html_header = False
        output = ['']

    elif path[0] == '_v0insecurekeyexchangeB' and path[1] in _TRUSTED_SERVERS:
        from base64 import b64encode
        result = http_request(path[1], '/_v0insecurekeyexchangeC/' + path[3] + '/' + b64encode(db.people.find_one({'name':path[2]})['publickey'].encode()).decode())
        if result[0] == 200:
            dereskey = result[1]
            name = path[4] + '@' + path[1]
            escapedname = name.replace('.', '_')
            db.people.update_one({'name':path[2]}, {'$set': {'remote_contacts.'+escapedname:{'_id':escapedname,'name':name,'publickey':dereskey}}})

    elif path[0] == '_v0insecurekeyexchangeC':
        todo=db.v0keyexchangetodo.find_one(ObjectId(path[1]))
        if todo:
            #path[2] er keyen og skal gemmes
            #vi skal returnere vores key    
            name = todo['remoteuser'] + '@' + todo['remoteserver']
            escapedname = name.replace('.', '_')
            from base64 import b64decode
            db.people.update_one({'_id': todo['localuser']}, {'$set': {'remote_contacts.'+escapedname:{'_id':escapedname,'name':name,'publickey':b64decode(path[2])}}})
            start_response('200 OK', [('Content-Type', 'application/octet-stream')])
            return [db.people.find_one(todo['localuser'])['publickey'].encode()]

    elif not user:
        response_status = '403 Unauthorized'
        output += ['<form method=post style="text-align:center"><h1>', env['HTTP_HOST'] ,'</h1><table align=center><tr><td align=left>',
                   esc(_('Name:')), '</td><td><input autofocus name=name></td></tr><tr><td align=left>', esc(_('Password:')),
                   '</td><td><input type=password name=pw></td></tr></table><button>', esc(_('Log in')),
                   #'</button><small><p>blokware v0.0.0.8.dev<br>Do what you love and the necessary<br>resources will follow. (Peter McWilliams)</p></small><img style="max-width:98%" src="' +
                   '</button><p><style>@import url(/blokware/skins/c64.css?' + random_alphanum(4) + '); *{font-family:monospace!important}</style><small><span style="color:white">LOAD "*",8,1</span><br><big><big><big>blokware 0.0.0.8.1</big></big></big></small></form>']
        if 'name' in post:
            candidateuser = db.people.find_one({'name':post['name'].value.strip()})

            if candidateuser and bcrypt.checkpw(post['pw'].value.encode(), candidateuser['pwhash']):
                #decrypt the user's private key (using their login password), then store a copy of that private key
                #for the duration of the login, encrypted with a random passphrase which is not stored on the server
                #but kept by the user agent in the login cookie along with the token
                prvkey = RSA.importKey(candidateuser['privatekey'], passphrase=str(bcrypt.hashpw(post['pw'].value.encode(), candidateuser['privatekey_salt'])))
                token = str(candidateuser['_id']) + random_alphanum(64)
                prvkey_passphrase = random_alphanum(256)
                db.logins.insert_one({'userid':candidateuser['_id'],'token':token,'privatekey':prvkey.exportKey(passphrase=prvkey_passphrase).decode(), 'ip':env['REMOTE_ADDR'], 'useragent':env['HTTP_USER_AGENT']})
                response_headers += [('set-cookie', 'blokwarelogin=' + token + '=' + prvkey_passphrase + '=; HttpOnly; Secure; Path=/;')]
                response_headers += [('location', env['PATH_INFO'])]
                response_status = '303 Welcome'
                include_html_header = False
                output = ['<h1><a href="/">Welcome</a></h1>']

    elif path == ['changepassword']:
        output = ['<h1>', esc(user['name']), '</h1>']
        if 'newpw' in post:
            if post['newpw'].value != post['newpw2'].value:
                output += ['<p>', esc(_('New passwords did not match; try again.')), '</p>']
            elif bcrypt.checkpw(post['oldpw'].value.encode(), user['pwhash']):
                set_user_password(db, user, post['newpw'].value, post['oldpw'].value)
                output += ['<p>', esc(_('Password changed.')), '</p>']
            else:
                output += ['<p>', esc(_("Didn't work, try again")), '</p>']
        output += ['<form method=post><table><tr><td>', esc(_('Old password')), '</td><td><input type=password name=oldpw></td></tr><tr><td>', esc(_('New password')), '</td><td><input type=password name=newpw></td></tr><tr><td>', esc(_('New password')), '</td><td><input type=password name=newpw2></td></tr></table><button>', esc(_('Change password')), '</button></form>']

    elif user['level'] == -1 and path == ['sitesettings']:
        if 'default_language' in post:
            db.config.find_one_and_replace({}, {'frontpage': post['frontpage'].value, 'default_language': post['default_language'].value, 'emailout':{'smtpserver':post['smtpserver'].value,'mailfrom':post['mailfrom'].value}})
            output = ['<p>Oki doki!</p>']
        else:
            output = ['<h1>Site settings</h1><form method=post>']
            output += ['<hr>Language for login screen and new users: <select name=default_language>'] + html_select_options(LANGUAGES, config['default_language']) + ['</select>']
            output += ['<hr>Front page: <select name=frontpage>'] + html_select_options(['events', 'threads', 'messages'], config['frontpage']) + ['</select>']
            output += ['<hr>Outgoing mail server for notifications: <input name=smtpserver value="' + esc(config['emailout']['smtpserver']) + '"> Sender address: <input name=mailfrom value="' + esc(config['emailout']['mailfrom']) + '">']
            output += ['<hr><button type=submit>Set</button></form>']

    elif user['level'] == -1 and path == ['usersadmin']:
        output = []
        highlight_id = None
        if 'mode' in post:
            if post['mode'].value == 'create_new_user' and len(post['new_user_name'].value.strip()) > 0:
                highlight_id = create_user(db, post['new_user_name'].value)#, post['email'].value)
            elif post['mode'].value == 'add_to_group':
                userlist = []
                for val in post:
                    if val[:14] == 'user_selected_':
                        userlist += [val[14:]]
                if userlist:
                    output = ['<h1>Add users to group</h1>Select group:'] + groups(db, '/add_users_to_group?users=' + ','.join(userlist) + '&amp;group=')

        if not output:
            users = db.people.find().sort([('level', 1), ('_id', -1)])
            output += ['<br><br><form method=post><input name=new_user_name placeholder="New user name"><button name=mode value=create_new_user class=visible_admin_action>Create</button><br><br>']
            output += ['<form><table><tr><th>Created</th><th>Name</th><th><button name=mode value=add_to_group class=visible_admin_action>Add to group...</button></th></tr>']
            for u in users:
                output += ['<tr' + ((highlight_id==u['_id'])*' class=highlight') + '>',
                           '<td>', formatdate(u['_id'].generation_time), '</td>',
                           '<td>', '<a href="/modify_user?' + str(u['_id']) + '" style="text-decoration:none;color:red;font-size:75%">⚙</a>',
                           '(admin)' * (u['level'] < 1), '<a href="/people/' + str(u['_id']) + '">', esc(u['name']), '</a></td>']
                is_checked = ('user_selected_' + str(u['_id']) in post) or (highlight_id==u['_id'])
                output += ['<td><label><input name=user_selected_' + str(u['_id']) + ((is_checked) * ' checked') + ' type=checkbox>Add to group</label></td>']
                output += ['</tr>']
            output += ['</table></form>']

    elif user['level'] == -1 and path in [['add_users_to_group'], ['remove_users_from_group']] and 'users' in qs and 'group' in qs:
        function = {'add_users_to_group': add_users_to_group, 'remove_users_from_group': remove_users_from_group}[path[0]]
        output = function(db, [ObjectId(uid) for uid in qs['users'].split(',')], ObjectId(qs['group']), 'group_membership_do' in post)

    elif user['level'] == -1 and path[0] == 'reparent_group':
        if not 'target' in qs:
            output += ['<p>Pick new parent group:</p>']
            output += groups(db, '.?target=')
        elif not 'go' in post:
            thisgroup = db.groups.find_one(ObjectId(path[1]))
            newparentgroup = db.groups.find_one(ObjectId(qs['target']))
            output += ['<p>Moving ', esc(thisgroup['name']), ' into ', esc(newparentgroup['name']), '</p>']
            if thisgroup['_id'] in walk_parent_groups(db, newparentgroup)[0]:
                output += ['<p>Are you crazy?</p>']
            else:
                output += ['<form method=post><button name=go class=visible_admin_action>Go</button></form>']
        else:
            newparentgroup_id = ObjectId(qs['target'])
            thisgroup = db.groups.find_one_and_update({'_id': ObjectId(path[1])}, {'$set': {'parent_group': newparentgroup_id}}, return_document=True)
            output += ["<h1>Group moved:</h1>"]
            output += group_breadcrumbs(*walk_parent_groups(db, thisgroup), True)
            thisgroup_members = db.people.find({'groups': thisgroup['_id']})
            output += ['<h2>As to its', str(thisgroup_members.count()), 'members:</h2>']
            output += add_users_to_group(db, [member['_id'] for member in thisgroup_members], newparentgroup_id, True)
            output += ['<br><hr><h2>New group tree:</h2>'] + groups(db, '/groups/')

    elif user['level'] == -1 and path == ['newgroups']:
        if 'names' not in post:
            if 'parent_group' in qs:
                output += ['<h2>Creating new subgroups of ', esc(db.groups.find_one(ObjectId(qs['parent_group']))['name']), '</h2>']
            else:
                output += ['<h2>Creating new top-level groups</h2>']
            output += ['<form method=post>Enter one group name per line:<br><textarea autofocus rows=10 cols=40 name=names></textarea><p><button class=visible_admin_action>Create</button></p></form>']
        else:
            newgroups = {}
            for name in post['names'].value.strip().split('\n'):
                name = name.strip()
                if name != '' and name not in newgroups:
                    newgroup = {'name': name, 'description':'', 'pending_memberships': []}
                    if 'parent_group' in qs: newgroup['parent_group'] = ObjectId(qs['parent_group'])
                    newgroups[name] = db.groups.insert_one(newgroup).inserted_id
            output = ['<h1>', str(len(newgroups)), 'group(s) created</h1><ul>'] + ['<li><a href="/groups/' + str(newgroups[g]) + '">' + esc(g) + '</a></li>' for g in newgroups] + ['</ul>']

    elif path == ['groups']:
        output = ['<h1>', esc(_('Groups:'))]
        if user['level'] == -1:
            output += ['<a href="/newgroups" class=visible_admin_action>+</a>']
        output += ['</h1>'] + groups(db, 'groups/')

    elif path[0] == 'groups' and len(path) == 2:
        try:
            id = ObjectId(path[1])
        except bson.errors.InvalidId:
            pass
        else:
            if user['level'] == -1 and 'group_name' in post:
                db.groups.update_one({'_id': id}, {'$set': {'description': post['group_description'].value, 'name': post['group_name'].value}})

            group = db.groups.find_one({'_id': id, 'private':{'$ne':True}})
            if group:
                pagetitle = group['name']
                if user['level'] == -1 and 'cancelpendingmembership' in post:
                    group = db.groups.find_one_and_update({'_id': id}, {'$pull': {'pending_memberships': ObjectId(post['cancelpendingmembership'].value)}}, return_document=True)
                if id in user['groups'] and 'approvemember' in post:
                    if ObjectId(post['approvemember'].value) in group['pending_memberships']:
                        #make that user a member of this group and its ancestor groups; encrypt each group's key with the user's public key.

                        #we need the current user's private key to decrypt each group's group key before we encrypt it for the target user.
                        decrypter = RSApadding(RSA.importKey(login['privatekey'], passphrase=prvkey_passphrase))
                        newmember = db.people.find_one(ObjectId(post['approvemember'].value))
                        newmember_encrypter = RSApadding(RSA.importKey(newmember['publickey']))
                        group_ids, group_names = walk_parent_groups(db, db.groups.find_one(id))
                        try:
                            newmember_newgroupkeys = {'groupkeys.' + str(gid): newmember_encrypter.encrypt(decrypter.decrypt(user['groupkeys'][str(gid)])) for gid in group_ids}
                        except KeyError:
                            output += ['<div style="padding:2em;background-color:orange;color:black;">Sorry, but you cannot approve someone as a member of this group because you are not yourself approved as a member of all of it&apos;s ancestor groups (' + ', '.join(group_names.values()) + ')</div><hr>']
                        else:
                            db.people.update_one({'_id': newmember['_id']}, {'$addToSet':{'groups':{'$each': group_ids}}, '$set': newmember_newgroupkeys})
                            group = db.groups.find_one_and_update({'_id': id}, {'$pull': {'pending_memberships': newmember['_id']}}, return_document=True)
                            output += ['<div style="padding:2em 2em 1em 2em;background-color:yellowgreen;color:black;">They have now been given a copy of your encryption key to the following group(s):<ul><li>', '</li><li>'.join([esc(group_names[gid]) for gid in group_ids]), '</li></ul></div>']
                    else:
                        output += ['<div style="padding:2em;background-color:orange;color:black;">(Too late: That approval request has already been handled in the meantime.)</div><hr>']
                output += showgroup(db, group, (id in user['groups']), (user['level'] == -1))

    elif user['level'] == -1 and path == ['modify_user']:
        if 'deleteuser' in post:
            db.people.delete_one({'_id':ObjectId(post['userid'].value)})
            output = ['pist vaek']
        if 'setemail' in post:
            theuser = db.people.find_one(ObjectId(post['userid'].value))
            theuser['email'] = post['email'].value
            db.people.replace_one({'_id': theuser['_id']}, theuser)
        if 'settlf' in post:
            theuser = db.people.find_one(ObjectId(post['userid'].value))
            theuser['tlf'] = post['tlf'].value
            db.people.replace_one({'_id': theuser['_id']}, theuser)
        if 'setadmin' in post:
            theuser = db.people.find_one(ObjectId(post['userid'].value))
            theuser['level'] = -1
            db.people.replace_one({'_id': theuser['_id']}, theuser)
        if 'setnotadmin' in post:
            theuser = db.people.find_one(ObjectId(post['userid'].value))
            theuser['level'] = 1
            db.people.replace_one({'_id': theuser['_id']}, theuser)
        if 'forgotpw' in post:
            theuser = db.people.find_one(ObjectId(post['userid'].value))
            theuser['pwhash'] = bcrypt.hashpw('elephant'.encode(), bcrypt.gensalt())
            rsa_key = RSA.generate(4096, Random.new().read)
            theuser['privatekey'] = rsa_key.exportKey()#smider den ukrypteret i databasen
            theuser['privatekey_salt'] = bcrypt.gensalt()
            theuser['groups'] = []
            theuser['groupkeys'] = {}
            db.people.replace_one({'_id': theuser['_id']}, theuser)
        if 'setgroupsforuser' in post:
            newgroups = []
            for group in db.groups.find():
                if 'group' + str(group['_id']) in post:
                    newgroups += [group['_id']]
            db.people.find_one_and_update({'_id': ObjectId(post['setgroupsforuser'].value)}, {'$set': {'groups': newgroups}})
            fuck = db.people.find_one(ObjectId(post['setgroupsforuser'].value))
            for fuckfuck in fuck['groups']:
                fuckfuck = str(fuckfuck)
                if not fuckfuck in fuck['groupkeys']:
                    fuck['groupkeys'][fuckfuck] = list(fuck['groupkeys'].values())[0]
            db.people.save(fuck)

        if not 'deleteuser' in post:
            item = db.people.find_one(ObjectId(env['QUERY_STRING']))
            output = ['<h1>', esc(item['name']), '</h1><form method=post><input type=hidden name=userid value=' + env['QUERY_STRING'] + '><input name=email value="', esc('' if not 'email' in item else item['email']), '" size=15><input type=submit name=setemail value=Set_Email><br><br><input placeholder="(husk +45)" name=tlf value="', esc('' if not 'tlf' in item else item['tlf']), '" size=15><input type=submit name=settlf value=Set_Tlf><br><br><input type=submit name=setadmin value=Set_Admin><input type=submit name=setnotadmin value=Set_Not_Admin><br><br><input type=checkbox onchange="this.nextSibling.disabled=!this.checked"><input onclick="return confirm(\'hvis de har skrevet noget eller oprettet begivenheder saa vil det her give problemer. slet bruger?\')" type=submit name=deleteuser value=Slet_Bruger disabled><br><br><input type=checkbox onchange="this.nextSibling.disabled=!this.checked"><input type=submit name=forgotpw value="set password to elephant" disabled></form><h2>Manuel gruppekontrol:</h2><form method=post>']
            output += [' <label><input type=checkbox name=group' + str(group['_id']) + (' readonly onchange="this.checked=true"' if 'private' in group else ' onchange="this.parentNode.parentNode.lastChild.style.visibility=\'\'"') +
                       (' checked' if group['_id'] in item['groups'] else '') + '>' + esc(group['name']) + '</label>' for group in db.groups.find({'$or':[{'_id':{'$in':item['groups']}},{'private':{'$ne':True}}]})]
            output += ['<input type=hidden name=setgroupsforuser value="' + str(item['_id']) + '"><input type=submit value="Sæt" style="visibility:hidden"></form>']

            output = ['<br>resterne af det oprindelige adminpanel:<div style="border:10px inset red;background-color:pink;">'] + output + ['</div>']
            output += ['Aktive logins:<ol>'] + ['<li>fra ' + l['ip'] + ' ' + formatdate(l['_id'].generation_time) + ' med ' + esc(l['useragent']) + '</li>' for l in db.logins.find({'userid':item['_id']})] + ['</ol><hr>Har android-notification-ID: ' + ('nej' if not 'evilempireid' in item else item['evilempireid'])]

    elif path == ['usersettings']:
        def setpref(pref, value):
            db.people.find_one_and_update({'_id': user['_id']}, {'$set':{pref: value}})
            user[pref] = value
        if 'language' in post:
            set_language(env, post['language'].value)
            setpref('pref_language', post['language'].value)
        if 'skin' in post:
            setpref('pref_skin', post['skin'].value)

        def prefswitcher(organ, key, options):
            return ['<h1>', esc(organ), '</h1>'] + ['<input type=submit name=' + key + ' value="' + option + '">' for option in options] + ['<br>']
        output += ['<form method=post>']
        output += prefswitcher(_('Tongue'), 'language', LANGUAGES)
        output += prefswitcher(_('Skin'), 'skin', SKINS)
        output += ['</form>']

    elif path == ['ur']:
        tidnu = str(datetime.now().second)
        output = ['Ved start viser sekundviseren ', tidnu, '<script id=news_insert_marker>fetch_news.position_info="' + tidnu + '";</script>']
        
    elif path == ['messages']:
        decrypter = RSApadding(RSA.importKey(login['privatekey'], passphrase=prvkey_passphrase))
        output = comms(db, user, decrypter, fucking_webkit='AppleWebKit' in env['HTTP_USER_AGENT'] and 'Chrom' not in env['HTTP_USER_AGENT'])

    elif path == ['messages', 'new']:
        output = ['<h1>', esc(_('New message')), '</h1>', esc(_('To:')),' <input size=16 onkeydown=\'document.querySelector("select").disabled=false;document.querySelector("select").value=".";this.dataset.inhibit_jump_once=(event.keyCode>123||(event.keyCode>44&amp;&amp;event.keyCode<112)||event.keyCode==32||(event.keyCode==8&amp;&amp;this.value.length>0))?"true":"false";if(event.keyCode==13||event.keyCode==39)this.oninput();\' oninput=\'if(this.dataset.inhibit_jump_once=="true"){this.dataset.inhibit_jump_once="false";return;}this.value=this.value.split(" (")[0];this.onblur();if (document.getElementById("sendbutton").disabled==false){setTimeout("document.querySelector(&apos;textarea&apos;).focus();"), 1}\' onblur=\'usermatch=document.getElementById("useroption_" + this.value.toLowerCase().trim().replace(/ /g, "_"));document.getElementById("sendbutton").disabled=(usermatch==null);if (usermatch)document.getElementById("newmsgform").action="/messages/user/"+usermatch.dataset.name;\' type=search list=users autofocus><datalist id=users>']
        for option in db.people.find().sort('name'):
            their_groups = db.groups.find({'_id': {'$in': option['groups']}, 'private': {'$ne': True}}).sort('_id', -1)
            groupname = ' (' + their_groups[0]['name'] + ')' if their_groups.count() > 0 else ''
            output += ['<option id="useroption_' + esc(option['name'].lower().replace(' ', '_')) + '" data-name="' + esc(option['name']) + '">' + esc(option['name'] + esc(groupname))]
        output += ['</datalist> @ <select disabled onchange=\'document.getElementById("sendbutton").disabled=true;if(this.value!=".")keyExchangeFuckery(this.value);\'><option value="." selected>' + env['HTTP_HOST'] + '</option>'] + [('<option>' + esc(ts) + '</option>') if ts != env['HTTP_HOST'] else '' for ts in _TRUSTED_SERVERS] + ['</select><form method=post id=newmsgform><textarea required autofocus style="width:100%;height:10em;" name=msg></textarea><button id=sendbutton disabled>Send</button></form>']
        output+=['<style>@media all and (max-width: 640px) {select{max-width:9em}}</style><script>function keyExchangeFuckery(s){document.getElementById("sendbutton").disabled=false;document.getElementById("newmsgform").action="/messages/user/"+document.querySelector("input").value+"@"+s; document.body.appendChild(document.createElement("iframe")).src="/_v0insecurekeyexchange/"+s+"/"+document.querySelector("input").value;document.querySelector("iframe").style.border="none"}</script>']

    #/messages/user/something
    elif path[0] == 'messages' and len(path) == 3 and path[1] == 'user':
        otheruserref = path[2]
        otheruser = None

        if '@' in otheruserref:
            try:
                otheruser = user['remote_contacts'][otheruserref.replace('.', '_')]
            except KeyError:
                output = ["der findes vist ikke helt en bruger der hedder det. (indtil videre skal du vaere ganske praecis med store og smaa bogstaver og saadan.)"]#ikke implementeret: foerstegangskommunikation med en given fjern bruger"]
        else:
            otheruser = db.people.find_one({'name': otheruserref})
        
        if otheruser:
            if 'msg' in post:
                def _OLDMSGFORMATCOMPATencrypt(clear_msg): key = Random.new().read(32);iv = Random.new().read(AES.block_size);aes_cipher = AES.new(key, AES.MODE_CFB, iv);return (iv + key, aes_cipher.encrypt(clear_msg))
                key, encrypted_msg = _OLDMSGFORMATCOMPATencrypt(post['msg'].value)#XXX change this to use encrypt()/decrypt() next time we break format compat anyway

                msgkeys = {str(person['_id']): RSApadding(RSA.importKey(person['publickey'])).encrypt(key) for person in [user, otheruser]}
                
                message_id = db.messages.insert_one({'from': user['_id'], 'to': otheruser['_id'], 'keys': msgkeys, 'msg': encrypted_msg}).inserted_id
                if '@' in otheruserref:
                    recipient_server = otheruser['name'].split('@')[-1]
                    idkey = str(message_id) + hex(int.from_bytes(msgkeys[otheruser['_id']], 'big'))[-42:]
                    db.messages_outgoing.insert_one({'_id': message_id, 'idkey': idkey, 'server': recipient_server})
                    http_request(recipient_server, '/_v0msgsync_init?s=' + env['HTTP_HOST'] + '&k=' + idkey)
                else:
                    notify_user(env, db, otheruser, env['HTTP_HOST'] + '/messages/user/' + urlesc(user['name']), post['msg'].value, user['name'])

            decrypter = RSApadding(RSA.importKey(login['privatekey'], passphrase=prvkey_passphrase))
            pagetitle = otheruser['name']
            output = comms_with_user(db, otheruser, user, decrypter)

    elif path == ['people']:
        output = ['<hr>'] + ['<a href="/people/' + str(item['_id']) + '">' + esc(item['name']) + '</a><hr>' for item in db.people.find().sort('name')]

    elif path == ['people', 'changedescription']:
        output = showuser(db, user, True, None, True)

    #/people/someone and /people/someone/threads
    elif path[0] == 'people' and (len(path) == 2 or (len(path) == 3 and path[2] == 'threads')):
        try:
            id = ObjectId(path[1])
        except bson.errors.InvalidId:
            pass
        else:
            if 'description' in post and id == user['_id']:
                user['description'] = post['description'].value
                db.people.replace_one({'_id': user['_id']}, user)
            peoplum = db.people.find_one(id)
            if peoplum:
                pagetitle = peoplum['name']
                if len(path) < 3:
                    threads_to_list = None
                else:
                    threads_to_list = []
                    raw_threads_to_list = db.threads.find({'group': {'$in': user['groups']}, 'messages.author': peoplum['_id']}).sort([('lastupdate', -1)])
                    user_decrypter = loaduserdecrypter(login, prvkey_passphrase)
                    groupkeys = {}
                    for item in raw_threads_to_list:
                        if not item['group'] in groupkeys: groupkeys[item['group']] = loadgroupkey(item['group'], user, user_decrypter)
                        decrypt_values(item, ['title'], groupkeys[item['group']])
                        threads_to_list += [item]
                output = showuser(db, peoplum, user['_id'] == id, threads_to_list, show_admin_actions=(user['level'] == -1))

    elif path in [['threads'], ['events'], ['events', 'all'], ['pages']]:
        try:
            groupid = ObjectId(qs['group']) if 'group' in qs and qs['group'] != '' else None
        except bson.errors.InvalidId:
            pass
        else:
            if groupid and (not groupid in user['groups']):
                output = [_('<p>You are not a member of this group.</p>')]
            elif path[0] == 'threads':
                output += threads(db, user['groups'], user['groupkeys'], loaduserdecrypter(login, prvkey_passphrase), groupid)
            elif path[0] == 'events':
                output += events(db, user['groups'], user['groupkeys'], loaduserdecrypter(login, prvkey_passphrase), groupid, show_old=(len(path) == 2 and path[1] == 'all'))
            elif path[0] == 'pages':
                output += pages(db, user['groups'], user['groupkeys'], loaduserdecrypter(login, prvkey_passphrase), groupid)

    elif path == ['threads', 'new']:
        if 'title' in post or 'event' in post:
            thread = {'lastupdate': ObjectId(), 'messages': [],} #perhaps redundant now when threads only have messages (not "ideas"), so lastmessagecreationtime==threadlastupdatetime...?

            if 'event' in post:
                event = db.events.find_one(ObjectId(post['event'].value))
                thread['group'] = event['group']
            else:
                thread['group'] = ObjectId(post['group'].value)

            if thread['group'] not in user['groups']:
                output = [_('<p>You are not a member of this group.</p>')]
            else:
                user_decrypter = loaduserdecrypter(login, prvkey_passphrase)
                groupkey = loadgroupkey(thread['group'], user, user_decrypter)
                if 'event' in post:
                    #FIXME as written this allows someone to make a new thread for an event that already has a thread
                    thread['title'] = event['title']
                    cleartitle = decrypt(thread['title'], groupkey)
                    thread['messages'] = [{'author': user['_id'],
                                           'event_id': event['_id'],
                                           'html': encrypt(esc(_('This thread has been created for discussing the event')) + ' "' + esc(decrypt(event['title'], groupkey)) + '"', groupkey),
                                           '_id': ObjectId(),
                                         }]
                else:
                    assert len(post['title'].value) <= MAXLEN['title']
                    cleartitle = post['title'].value
                    thread['title'] = encrypt(cleartitle, groupkey)

                thread['messages'] += [{'author':user['_id'], '_id':ObjectId(), 'html': encrypt(safehtml(post['msghtml'].value), groupkey)}]

                doppelgaengers = db.threads.find({'_id': {'$gt': ObjectId.from_datetime(datetime.utcnow() - timedelta(minutes=15))}, 'messages.author': thread['messages'][0]['author'], 'group': thread['group']})
                if doppelgaengers.count() and {False} != set([decrypt(dg['title'], groupkey) == cleartitle for dg in doppelgaengers]): #uses same logic as for events
                    output += ['<h1>Doppelg&auml;nger detected</h1>It appears that you quite recently created an identical thread:<br>']
                    doppelgaengers.rewind()
                    for dg in doppelgaengers:
                        decrypt_values(dg, ['title'], groupkey)
                        if dg['title'] == cleartitle:
                            output += listthread(db, dg)
                    output += ['<p><small>In Norse mythology, a <em>vard&oslash;ger</em> is a ghostly double who precedes a living person and is seen performing their actions in advance. This is not relevant to your thread, though.</small></p>']
                else:
                    id = db.threads.insert_one(thread).inserted_id
                    if 'event' in post:
                        db.events.find_one_and_update({'_id': event['_id']}, {'$set': {'thread': id}})
                    notify_group(env, db, thread, cleartitle, env['HTTP_HOST'] + '/threads/' + str(id), 'Ny tråd: ', user['name'])

                    output = threads(db, user['groups'], user['groupkeys'], user_decrypter, thread['group'], id)
        elif 'event' in qs:
            try:
                event_id = ObjectId(env['QUERY_STRING'][6:])
            except bson.errors.InvalidId:
                pass
            else:
                output = showthread(db, {'title':'','messages':[], 'event': event_id})
        else:
            output = showthread(db, {'title':'','messages':[]}, user['groups'])

    elif path[0] == 'threads' and len(path) == 2:
        try:
            id = ObjectId(path[1])
        except bson.errors.InvalidId:
            pass
        else:
            item = db.threads.find_one(id)
            if item:
                if not item['group'] in user['groups']:
                    item = None
                    output = [_('<p>You are not a member of this group.</p>')]
                else:
                    groupkey = loadgroupkey(item['group'], user, loaduserdecrypter(login, prvkey_passphrase))
                    if 'msghtml' in post:
                        item = db.threads.find_one_and_update({'_id': id},
                            {'$push':
                                {'messages':
                                    {'author':user['_id'],
                                     'html':encrypt(safehtml(post['msghtml'].value), groupkey),
                                     '_id':ObjectId(),
                                    }
                                },
                             '$set':
                                {'lastupdate':ObjectId()}
                            },
                            return_document = True
                        )

                    decrypt_values(item, ['title', ('messages', ['html'])], groupkey)
                    pagetitle = item['title']
                    output = showthread(db, item)

    #/events/new and /events/something/edit
    elif path[0] == 'events' and ((len(path) == 2 and path[1] == 'new') or (len(path) == 3 and path[2] == 'edit')):
        if path[1] == 'new':
            item = {'title':'', 'descriptionhtml':'', 'start':'', 'end':'', 'mode': 'event'}
        else:
            try:
                id = ObjectId(path[1])
            except bson.errors.InvalidId:
                item = None
            else:
                item = db.events.find_one(id)
                if item and item['author'] != user['_id']:
                    item = None

        if item and 'title' not in post:
            if path[1] == 'new' and 'thread' in qs:
                try:
                    threadid = ObjectId(qs['thread'])
                except bson.errors.InvalidId:
                    pass
                else:
                    output = showevent(db, {'thread': threadid, 'title':'', 'descriptionhtml':'', 'start':'', 'end':'', 'mode': 'event'})
            elif path[1] == 'new' and 'template_event_id' in post:
                try:
                    id = ObjectId(post['template_event_id'].value)
                except bson.errors.InvalidId:
                    pass
                else:
                    template = db.events.find_one(id)
                    if template and template['group'] in user['groups']:
                        for foo in ['title', 'descriptionhtml', 'mode', 'group', 'thread']:
                            if foo in template:
                                item[foo] = template[foo]
                        groupkey = loadgroupkey(item['group'], user, loaduserdecrypter(login, prvkey_passphrase))
                        decrypt_values(item, ('title', 'descriptionhtml'), groupkey)
                        output = showevent(db, item)
            else:
                if path[1] != 'new': #could just as well be: if '_id' in item
                    groupkey = loadgroupkey(item['group'], user, loaduserdecrypter(login, prvkey_passphrase))
                    decrypt_values(item, ('title', 'descriptionhtml'), groupkey)

                output = showevent(db, item, user['groups'], '_id' in item)

        elif item:
            assert len(post['title'].value) <= MAXLEN['title']
            if path[1] == 'new':
                if 'group' in post:
                    group = db.groups.find_one(ObjectId(post['group'].value))
                    if group:
                        if group['_id'] in user['groups']:
                            item['group'] = group['_id']
                        else:
                            item = None
                            output = [_('<p>You are not a member of this group.</p>')]
                    else:
                        item = None
                if 'thread' in post:
                    thread = db.threads.find_one(ObjectId(post['thread'].value))
                    if thread:
                        if thread['group'] in user['groups']:
                            item['thread'] = thread['_id']
                            item['group'] = thread['group']
                        else:
                            item = None
                            output = [_('<p>You are not a member of this group.</p>')]
                    else:
                        item = None

            if item:
                try:
                    item['start'] = datetime.strptime(post['start'].value[:16].replace(' ', 'T'), '%Y-%m-%dT%H:%M')
                    if post['end'].value == '':
                        item['end'] = item['start']
                    else:
                        item['end'] = datetime.strptime(post['end'].value[:16].replace(' ', 'T'), '%Y-%m-%dT%H:%M')
                except ValueError:
                    item = None
                    output = ['<h1>Incorrect date/time format</h1><p>The beginning and ending dates need to be written in the format <strong>YYYY-MM-DD HH:MM</strong> (for example <strong>2009-09-26 16:20</strong>).</p>']

            if item:
                user_decrypter = loaduserdecrypter(login, prvkey_passphrase)
                groupkey = loadgroupkey(item['group'], user, user_decrypter)
                
                item['title'] = encrypt(post['title'].value, groupkey)
                item['descriptionhtml'] = encrypt(safehtml(post['descriptionhtml'].value), groupkey)
                if path[1] != 'new':
                    db.events.replace_one({'_id': item['_id']}, item)
                    output = events(db, user['groups'], user['groupkeys'], user_decrypter, item['group'], id)
                else:
                    item['author'] = user['_id']
                    item['mode'] = post['mode'].value
                    if item['mode'] == 'vote':
                        item['opinions'] = {}

                    comparebase = item.copy()
                    comparebase.pop('title')
                    comparebase.pop('descriptionhtml')
                    doppelgaengers = db.events.find(comparebase) #find events with identical non-encrypted properties
                    #if there are any, decrypt the titles and test if any is a match:
                    if doppelgaengers.count() and {False} != set([decrypt(dg['title'], groupkey) == post['title'].value for dg in doppelgaengers]):
                        output = ['<h1>Doppelg&auml;nger detected</h1>It appears that you already created an identical event:<br>']
                        #(we do the work of decrypting and comparing again now, for the control-flow convenience of being able to use a single if statement above)
                        doppelgaengers.rewind()
                        for dg in doppelgaengers:
                            decrypt_values(dg, ['title'], groupkey)
                            if dg['title'] == post['title'].value:
                                output += listevent(db, dg)
                        output += ['<p><small>In Norse mythology, a <em>vard&oslash;ger</em> is a ghostly double who precedes a living person and is seen performing their actions in advance. This is not relevant to your event, though.</small></p>']
                    else:
                        id = db.events.insert_one(item).inserted_id
                        if 'thread' in post:
                            db.threads.find_one_and_update({'_id': thread['_id']},
                                {'$push':
                                    {'messages':
                                        {'author':user['_id'],
                                         'event_id': id,
                                         'html': encrypt(esc(_('Created event:')) + ' ' + esc(post['title'].value), groupkey),
                                         '_id':ObjectId(),
                                        }
                                    },
                                 '$set':
                                    {'lastupdate':ObjectId()}
                                })
                        notify_group(env, db, item, post['title'].value, env['HTTP_HOST'] + '/events/' + str(id), 'Ny afstemning: ' if item['mode'] == 'vote' else 'Ny begivenhed: ', user['name'])
                        output = events(db, user['groups'], user['groupkeys'], user_decrypter, item['group'], id)

    elif path[0] == 'events' and len(path) == 2:
        try:
            id = ObjectId(path[1])
        except bson.errors.InvalidId:
            pass
        else:
            item = db.events.find_one(id)
            if not item:
                pass
            elif item['group'] not in user['groups']:
                output = [_('<p>You are not a member of this group.</p>')]
            else:
                groupkey = loadgroupkey(item['group'], user, loaduserdecrypter(login, prvkey_passphrase))
                if 'opinion' in post:
                    if item['end'] < datetime.now():
                        item = None
                        output = ["<p>This ballot is no longer accepting new opinions.</p>"]
                    else:
                        item = db.events.find_one_and_update({'_id': item['_id']},
                            {'$set':
                                {'opinions.' + str(user['_id']): encrypt(post['opinion'].value + ';' + post['opinioncomment'].value, groupkey)}
                            },
                            return_document = True
                        )

                if item:
                    if 'thread' in item:
                        #to avoid having to pass the groupkey to showevent() just for this, dig out the thread and decrypt it's title
                        item['thread_TITLE'] = decrypt(dbcacheget(db, 'threads', item['thread'], ['title'])['title'], groupkey)
                    decrypt_values(item, ['title', 'descriptionhtml', 'opinions'], groupkey)
                    pagetitle = item['title']
                    output = showevent(db, item, show_edit_link=(item['author']==user['_id']))

    elif path == ['pages', 'new']:
        if 'title' in post:
            group = ObjectId(post['group'].value)
            title = post['title'].value[:MAXLEN['title']]
            user_decrypter = loaduserdecrypter(login, prvkey_passphrase)
            groupkey = loadgroupkey(group, user, user_decrypter) #will crash if user not member of group, thus no need to check for it first
            item = {
                'group': group,
                'title': encrypt(title, groupkey),
                'revisions': [{'html': encrypt(safehtml(post['html'].value), groupkey), 'editor': user['_id'], '_id': ObjectId()}],
                'lookuphash': lookuphash(groupkey, title),
            }
            inserted_id = db.pages.insert_one(item).inserted_id
            output = pages(db, user['groups'], user['groupkeys'], user_decrypter, group, inserted_id)
        else:
            output = showpage(db, {'title': '', 'revisions': [{'html': ''}]}, user['groups'])

    elif path[0] == 'pages' and len(path) == 3:
        try:
            group = ObjectId(path[1])
        except bson.errors.InvalidId:
            pass
        else:
            if not group in user['groups']:
                output = [_('<p>You are not a member of this group.</p>')]
            else:
                groupkey = loadgroupkey(group, user, loaduserdecrypter(login, prvkey_passphrase))
                item = db.pages.find_one({'lookuphash': lookuphash(groupkey, path[2])}) #XXX when we get to hiding old revisions until user asks for them, it needs to happen here (before wasting cpu on decrypting old revisions)
                if not item:
                    output = showpage(db, {'title': esc(path[2]), 'group': group, 'revisions': [{'html': ''}]}, user['groups'])
                else:
                    if 'title' in post:
                        title = post['title'].value[:MAXLEN['title']]
                        item = db.pages.find_one_and_update({'_id': item['_id']}, {
                                '$set': {'title': encrypt(title, groupkey), 'lookuphash': lookuphash(groupkey, title)},
                                '$push': {'revisions': {'html': encrypt(safehtml(post['html'].value), groupkey), 'editor': user['_id'], '_id': ObjectId()}},
                            }, return_document=True)
                        #FIXME vi skal smide id'et på den revision vi redigerede udfra, med i postdata, og hvis det
                        #ikke laengere var nyeste nu, så skal vi smide en stor venlig advarsel med i output om at man
                        #lige har overskrevet en anden brugers aendringer fra revision xyz og vil man venligst lige
                        #merge. eventuelt skriv noticen ind i selve sidens data, evt. med diff eller et eller andet.

                    decrypt_values(item, ['title', ('revisions', ['html'])], groupkey)
                    pagetitle = item['title']
                    output = showpage(db, item)

    elif path[0] == '_news' and len(path) == 2:
        include_html_header = False
        output = ['n~\n', str(unreadcount(db, user)), '\n']
        if path[1] != '' and 'HTTP_REFERER' in env:
            referer = env['HTTP_REFERER'].split('/')
            if referer[-1] == 'ur':
                tidnu = str(datetime.now().second)
                if tidnu != path[1]:
                    output += ['Sekundviseren er nu paa <span style="color: #' + hashlib.md5(tidnu.encode()).hexdigest()[:6] + '">', tidnu, '</span>\n', tidnu,'\n']

            if referer[-3:-1] == ['messages', 'user']:
                otheruserref, lastmsgid = path[1].rsplit('|', 1)
                if '@' in otheruserref:
                    otheruser = user['remote_contacts'][otheruserref]
                else:
                    otheruserref = ObjectId(otheruserref)
                    otheruser = dbcacheget(db, 'people', otheruserref, ['name'])

                messages = db.messages.find({'$or': [{'to': otheruserref, 'from': user['_id']}, {'from': otheruserref, 'to': user['_id']}],
                                             '_id': {'$gt': ObjectId(lastmsgid)}})
                if messages.count() > 0:
                    decrypter = RSApadding(RSA.importKey(login['privatekey'], passphrase=prvkey_passphrase))
                    names = {party['_id']: party['name'] for party in [user, otheruser]}
                    for message in messages:
                        output += showmessage(db, user, decrypter, message, names) + ['<br>']
                    output += ['\n', str(otheruser['_id']), '|', str(message['_id']), '\n']

            elif referer[-2:-1] == ['threads']:
                highest_visible_message_id = ObjectId(path[1])
                thread_if_updated = db.threads.find_one({'_id': ObjectId(referer[-1]), 'messages._id': {'$gt': highest_visible_message_id}})
                if thread_if_updated: #hmmm... i'm commenting out |and thread_if_updated['group'] in user['groups']| so that we will fail-with-log-entry when looking for the groupkey in the user's key
                    groupkey = loadgroupkey(thread_if_updated['group'], user, loaduserdecrypter(login, prvkey_passphrase))
                    for message in thread_if_updated['messages']:
                        if message['_id'] > highest_visible_message_id:
                            decrypt_values(message, ['html'], groupkey)
                            output += showthreadmessage(db, thread_if_updated['_id'], message)
                    output += ['\n', str(message['_id']), '\n']

        output += ['~n']

    if not output: #non-logged in users will have the login screen as output already, so only logged-in users will see this 404
        response_status = pagetitle = '404 Not Found'
        output = ['<h1>Not Found</h1><p>The number you have dialed is not in service. Please check and try again.</p>']
        if env['PATH_INFO'][-1] == '/':
            response_status = '301 Lose the slash'
            response_headers += [('location', env['PATH_INFO'][:-1])]
            include_html_header = False

    if include_html_header:
        header = ['<!DOCTYPE html>\n<html>\n<head>',
                  '  <meta name=viewport content="width=device-width,initial-scale=1">',
                  '  <title>' + (esc(pagetitle) + ' - ' if pagetitle else '') + env['HTTP_HOST'] + '</title>',
                  '  <link rel=manifest href="/blokware.webmanifest">',
                  '  <link rel=stylesheet href="/blokware/layout.css">',
                  ] + ['  <link rel="stylesheet' + ('' if user and 'pref_skin' in user and user['pref_skin'] == skin else ' alternate') + '" href="/blokware/skins/' + skin + '.css" title="' + skin + '">' for skin in SKINS] + [
                  '  <link rel=icon href="' + get_resource_path('icon', env['HTTP_HOST']) + '">',
                  '  <script src="//cdn.tinymce.com/4/tinymce.min.js"></script>',
                  '  <script src="/blokware/script.js"></script>',
                  '  <meta name="apple-mobile-web-app-capable" content="yes"><!--until apple recognizes link rel=manifest -->',
                  '  <script src="/blokware/datetimepicker.js"></script><!--until firefox and safari support input type=datetime-local-->',
                  '</head>',
                  '<body>'
            ]
        if user:
            header += ['\n<div id=usernav>']
            if user['level'] == -1:
                header += ['  <span id=adminnav><span><br><a href="/usersadmin">Users</a><br><a href="/groups">Groups</a><br><a href="/sitesettings">Site settings</a><br></span>⚙ &bull;</span>']
                if db.adminlog.find_one(): header += ['<hr>CHECK SERVER LOG: ' + esc(repr(foo)) + '<hr>' for foo in db.adminlog.find()]
            header += [
                '  <a href="/people/' + str(user['_id']) + '">' + esc(user['name']) +
                '</a> &bull;\n  <a href="/logout">' + esc(_('log out')) +
                '</a>\n</div><div>&nbsp;</div>\n<nav>', nav(path[0], unreadcount(db, user)), '</nav><div>&nbsp;</div>\n'
            ]
            output += ['<small id=footer>' + _('FOOTER_HTML_HERE').format('.'.join(env['HTTP_HOST'].split('.')[-2:])) + '</small>']
        output = header + output + ['<div style="position:fixed;bottom:0;right:0" onmouseover="indicate(this);">&#x0950;</div>\n</body></html>']
    
    start_response(response_status, response_headers)
    if include_html_header:
        #for html, adding a linebreak between parts makes for neater looking source
        return [part.encode() + b'\n' for part in output]
    else:
        #for everything else, adding a linebreak between parts makes for mangled data
        return [part.encode() for part in output]

def dbcacheget(db, type, id, values):
    def None_or_a_lie_to_cover_for_deleted_users(): return None if type != 'people' else {'name': '[deleted user]', '_id': id}

    global dbcache

    if not 'dbcache' in globals():
        dbcache = {}

    output = {}
    dbitem = None
    for value in values:
        cachekey = type + str(id) + value
        if cachekey not in dbcache:
            if not dbitem:
                dbitem = db[type].find_one(id)
                if not dbitem:
                    return None_or_a_lie_to_cover_for_deleted_users()
            if value in dbitem:
                dbcache[cachekey] = dbitem[value]
            else:
                dbcache[cachekey] = None
        if dbcache[cachekey] is not None:
            output[value] = dbcache[cachekey]

    output['_id'] = id
    return output

def encrypt(cleartext, key=None):
    if key is None:
        randomkey = Random.new().read(32)
        return (encrypt(cleartext, randomkey), randomkey)

    iv = Random.new().read(AES.block_size)
    aes_cipher = AES.new(key, AES.MODE_CFB, iv)
    #stick a zero-value byte in front of the return value, as a "format version marker", in case we want to store things differently one day
    return b'\x00' + iv + aes_cipher.encrypt(cleartext)

def decrypt(iv_and_ciphertext, key):
    if iv_and_ciphertext[0] != 0: return iv_and_ciphertext #THIS LINE IS SAFE TO REMOVE; it is only for compatibility with pre-blokware0.0.0.8.x databases

    try:
        aes_cipher = AES.new(key, AES.MODE_CFB, iv_and_ciphertext[1:17])
        return aes_cipher.decrypt(iv_and_ciphertext[17:]).decode()
        #17 == AES.block_size + 1 byte for our format version marker
    except ValueError as e:
        #at least until we handle the case of removing all users from a group and
        #then adding a user, who will then see preexisting threads and events which
        #they don't have the right key for, we don't want this to fail hard.
        return '[DECRYPTION FAILED] ' + esc(repr(iv_and_ciphertext))

def loaduserdecrypter(login, prvkey_passphrase):
    return RSApadding(RSA.importKey(login['privatekey'], passphrase=prvkey_passphrase))

def loadgroupkey(groupid, either_whole_user_or_just_their_groupkeys, user_decrypter):
    try:
        groupkeys = either_whole_user_or_just_their_groupkeys['groupkeys']
    except KeyError:
        groupkeys = either_whole_user_or_just_their_groupkeys
    return user_decrypter.decrypt(groupkeys[str(groupid)])

def decrypt_values(item, fields_to_decrypt, groupkey):
    '''
    >>> def decrypt(str, key):
    ...  return 'decrypt('+str+')!'
    ... 
    >>> foo = {'a': 'aaa', 'b': 'bbb', 'c': 'ccc', 'd': 'ddd', 'e': {'m': 'mmm', 'n': 'nnn', 'o': 'ooo', 'p': 'ppp'}, 'f': [{'w': 'www1', 'x': 'xxx1', 'y': 'yyy1', 'z': 'zzz1'}, {'v': 'vvv2', 'w': 'www2', 'x': 'xxx2', 'y': 'yyy2'}]}
    >>> decrypt_values(foo, ['b','d','e',('f',['y','x'])], None)
    >>> print(foo)
    {'f': [{'w': 'www1', 'y': 'decrypt(yyy1)!', 'z': 'zzz1', 'x': 'decrypt(xxx1)!'}, {'w': 'www2', 'y': 'decrypt(yyy2)!', 'v': 'vvv2', 'x': 'decrypt(xxx2)!'}], 'b': 'decrypt(bbb)!', 'a': 'aaa', 'd': 'decrypt(ddd)!', 'c': 'ccc', 'e': {'o': 'decrypt(ooo)!', 'n': 'decrypt(nnn)!', 'p': 'decrypt(ppp)!', 'm': 'decrypt(mmm)!'}}
    '''
    for selector in fields_to_decrypt:
        if type(selector) is type('') and selector in item: #ignore non-existant fields (specifically because some events have 'opinions' and some don't)
            if type(item[selector]) is type({}):
                for field in item[selector]:
                    item[selector][field] = decrypt(item[selector][field], groupkey)
            else:
                item[selector] = decrypt(item[selector], groupkey)
        elif type(selector) is type(()):
            for subdict in item[selector[0]]:
                decrypt_values(subdict, selector[1], groupkey)

def lookuphash(secret, title):
    return hashlib.sha256(hashlib.sha256(secret).digest() + title.encode()).hexdigest()

def random_alphanum(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

#XXX creating new users with blank password by default means anyone with only read-access to
#mongo operations will be able to get their private key (since it will be inserted initially
#into the database encrypted with the bcrypt hash of an empty string). fix would probably be
#to not create the key until the user signs in and chooses a password (then messaging would
#probably have to have a special-case for attempting to write to a user who has no public key
#yet); or alternatively, to require passwords on initial user creation (maybe autogenerated,
#long, and with an "activation"-link that includes it)
def create_user(db, name, email='', password='', level=1):
    rsa_key = RSA.generate(4096, Random.new().read)
    groupid = db.groups.insert_one({'private': True, 'name': 'Mine private ting', 'description':'', 'pending_memberships': []}).inserted_id
    groupkey = RSApadding(rsa_key).encrypt(encrypt('')[1])
    user = db.people.find_one(db.people.insert_one({'groups': [groupid],
                                                   'groupkeys': {str(groupid): groupkey},
                                                   'level': level,
                                                   'publickey': rsa_key.publickey().exportKey().decode(),
                                                   'description': '',
                                                   'email': email.strip(),
                                                   'name': name.strip()}).inserted_id)

    user['privatekey'] = rsa_key.exportKey()
    user['privatekey_salt'] = bcrypt.gensalt()
    set_user_password(db, user, password)
    return user['_id']

def set_user_password(db, user, newpw, currentpw=None):
    user['pwhash'] = bcrypt.hashpw(newpw.encode(), bcrypt.gensalt())
    privatekey = RSA.importKey(user['privatekey'], passphrase=str(bcrypt.hashpw(str(currentpw).encode(), user['privatekey_salt'])))
    user['privatekey'] = privatekey.exportKey(passphrase=str(bcrypt.hashpw(newpw.encode(), user['privatekey_salt']))).decode()
    db.people.replace_one({'_id': user['_id']}, user)

def add_users_to_group(db, userids, groupid, run=False):
    group_ids, group_names = walk_parent_groups(db, db.groups.find_one(groupid))
    
    if run:
        def add_members_to_empty_groups():
            if not empty_groups_ids:
                #feel free to replace the following line with simply:  return []
                return ['<small style="background:yellow">[debug: There were no inner empty groups to add the members directly to.]</small>']
            #to add a member to a group WITH pre-existing members, that group's encryption key needs to
            #be copied from a pre-existing member's encrypted storage and reencrypted for the new member.
            #empty groups (those with no members) are easier: we just make up a random encryption key for
            #each group, encrypt those keys with each user-to-add's public key, and insert that into the
            #database along with each user's record of their membership of the group.
            groupkeys = {gid: encrypt('')[1] for gid in empty_groups_ids}
            for uid in userids:
                user = db.people.find_one(uid)
                user_encrypter = RSApadding(RSA.importKey(user['publickey']))
                user_newgroupkeys = {'groupkeys.' + str(gid): user_encrypter.encrypt(groupkeys[gid]) for gid in groupkeys}
                db.people.update_one({'_id': uid}, {'$addToSet':{'groups':{'$each': empty_groups_ids}}, '$set': user_newgroupkeys})
            return ['<p>They are now members of the following group(s) (which were empty):</p><ol>'] + ['<li><a href="/groups/' + str(gid) + '">' + esc(group_names[gid]) + '</a></li>' for gid in empty_groups_ids] + ['</ol>']

        empty_groups_ids = [] #a list of those of the groups that have no pre-existing members, which we can directly add the users to without approval
        for group in group_ids: #walk from the selected group towards it top-level ancestor; stop at the first group that's NOT empty
            if not db.people.find_one({'groups': group}): #the group we've reached is empty
                empty_groups_ids += [group]
            else: #we have a group with members
                output = add_members_to_empty_groups() #add the users directly to the groups we can
                #and for the group that already has members, check whether these users are all among them:
                for already_member in db.people.find({'_id': {'$in': userids}, 'groups': group}):
                    userids.remove(already_member['_id'])
                if not userids: #all the users-to-add are already members of this ancestor group, so we're done
                    return output + ['<p>They were already members of <b>' + esc(group_names[group]) + '</b>.</p>']
                else: #at least one of the new-users-to-add are NOT among the members of this group,
                      #so add a pending-membership-request for one of the existing members to approve:
                    db.groups.update_one({'_id': group}, {'$addToSet':{'pending_memberships':{'$each': userids}}})
                    output += ['<p>Pending approval of an existing member of <b>' + esc(group_names[group]) +
                               '</b>, they will be added to the following group(s):</p><ol>']
                    output += ['' if gid in empty_groups_ids else ('<li><a href="/groups/' + str(gid) + '">' +
                               esc(group_names[gid]) + '</a></li>') for gid in group_ids]
                    output += ['</ol>']
                    return output

        #if we got this far, all ancestor groups all the way to the top are empty, so add the users directly to all of them:
        return add_members_to_empty_groups()
    else:
        group_ids.reverse()
        groupcount = '' if len(group_ids) == 1 else ' ' + str(len(group_ids)) + ' groups'
        output = ['<form method=post><p>', esc('You are starting the process to make someone a member of' + groupcount + ':') + '</p>']
        output += ['<ul><li>' + esc(group_names[gid]) for gid in group_ids]
        output += ['</li></ul>' * len(group_ids)]
        output += ['<button name=group_membership_do class=visible_admin_action>That&apos;s right</button></form>']
        return output

def remove_users_from_group(db, userids, groupid, run=False):
    group_ids, group_names = walk_child_groups(db, [db.groups.find_one(groupid)])
    
    if run:
        db.people.update_many({'_id':{'$in':userids}}, {'$unset': {'groupkeys.' + str(gid): '' for gid in group_ids}, '$pull':{'groups':{'$in': group_ids}}})
        output = ['<p>', esc('They have been removed from whichever of the following groups they were in:') + '</p><ul><li>' + '</li><li>'.join([esc(group_names[gid]) for gid in group_ids]) + '</li></ul>']
    else:
        output = ['<form method=post><h1>You are about to remove someone from the group <b>' + esc(group_names[group_ids.pop(0)]) + '</b>.</h1>']
        if group_ids:
            output += ['<p>If they&apos;re also a member of any of the <em>subgroups</em> of the aforementioned group, then they will be removed from those as well: ' +
                       ', '.join([esc(group_names[gid]) for gid in group_ids]) + '.</p>']
        output += ['<button name=group_membership_do class="visible_admin_action destructive">Do it</button></form><p><small><em>Be aware that removing the last user from a group will irrevocably destroy the last copy of the decryption key for that group&apos;s threads and events.</em></small></p>']
    return output

def walk_parent_groups(db, group):
    group_ids, group_names = [], {}
    while group:
        group_ids += [group['_id']]
        group_names[group['_id']] = group['name']
        group = db.groups.find_one(group['parent_group']) if 'parent_group' in group else None

    return group_ids, group_names

def walk_child_groups(db, groups):
    group_ids, group_names = [], {}
    while groups:
        group = groups.pop()
        group_ids += [group['_id']]
        group_names[group['_id']] = group['name']
        groups += list(db.groups.find({'parent_group': group['_id']}))

    return group_ids, group_names

def esc(text):
    return "".join({
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }.get(c,c) for c in text)

def safehtml(source):
    #XXX use "bleach" library for this?
    source = source.replace('<div>', '<br>').replace('</div>', '') #chrome inserts divs when enter is pressed in contenteditable elements.
    return "".join({
    ">": "&gt;",
    "<": "&lt;",
    #why is it we only escape lt and gt? because tinymce quotes the others for us and we dont want them twicequoted? no, doesnt make sense..?
    }.get(c,c) for c in source
        ).replace('&lt;br&gt;', '<br>'
        ).replace('&lt;br /&gt;', '<br>'
        ).replace('&lt;b&gt;', '<b>'
        ).replace('&lt;/b&gt;', '</b>'
        ).replace('&lt;i&gt;', '<i>'
        ).replace('&lt;/i&gt;', '</i>'
        ).replace('&lt;strong&gt;', '<strong>'
        ).replace('&lt;/strong&gt;', '</strong>'
        ).replace('&lt;em&gt;', '<em>'
        ).replace('&lt;/em&gt;', '</em>'
        ).replace('&lt;span style="text-decoration: underline;"&gt;', '<span style="text-decoration: underline;">'
        ).replace('&lt;/span&gt;', '</span>'
        ).replace('&lt;sub&gt;', '<sub>'
        ).replace('&lt;/sub&gt;', '</sub>'
        ).replace('&lt;sup&gt;', '<sup>'
        ).replace('&lt;/sup&gt;', '</sup>'
        )

def set_language(env, language):
    if language == 'sa': #pythons normalization doesn't work for sanskrit
        new_locale = 'sa_IN.UTF-8'
    else:
        new_locale = [language, 'UTF-8']

    try:
        locale.setlocale(locale.LC_TIME, new_locale)
    except locale.Error:
        pass

    gettext.translation(language, '/'.join(env['SCRIPT_FILENAME'].split('/')[:-1]), ['languages']).install()

def nav(current_path, msgcount):
    if msgcount == 0:
        msgnotifier = ''
    elif msgcount == 1:
        msgnotifier = '✉ '
    else:
        msgnotifier = '✉' + str(msgcount) + ' '
    
    bits = ['<a href="/' + path + '"' + (' class=current' if current_path == path else '') + '>' + title + '</a>'
            for path, title in [('events', esc(_('Events'))), ('threads', esc(_('Threads'))),
            ('messages', '<span id=newmsgs>' + msgnotifier + '</span>' + esc(_('Messages')))]]
    return '  ' + ' |\n  '.join(bits)

def get_resource_path(resource, hostname):
    if resource == 'cover' and hostname in LOGIN_SCREEN_IMAGES:
        images = LOGIN_SCREEN_IMAGES[hostname]
        return images[random.randint(0, len(images) - 1)]
 
    if resource == 'icon':
        hostname = '.'.join(hostname.split('.')[-2:])

    return '/blokware/siteimages/' + hostname + '.' + resource + '.png'

def unreadcount(db, recipient, sender=None):
    condition = {'to': recipient['_id'], 'read': {'$exists': False}}
    if sender:
        condition['from'] = sender['_id']
    return db.messages.find(condition).count()

def formatdate(date, include_time=True, include_seconds=True): #set include_time to -1 to exclude date
    if date.tzinfo:
        #FIXME bad voodoo; will break when viewing things from before DST change?
        import calendar
        timestamp = calendar.timegm((datetime.strptime( str(date)[:19], '%Y-%m-%d %H:%M:%S')).timetuple())
        date = datetime.fromtimestamp(timestamp)

    if include_time == -1:
        output = date.strftime('%X')
    elif include_time:
        output = date.strftime('%c')
    else:
        output = date.strftime('%c').replace(date.strftime('%X'), '')
    
    output = output.strip()
    if not include_seconds:
        if output[-3] == ':':
            output = output[:-3]
        elif output[-3:] in [' AM', ' PM']:
            output = output[:-6] + output[-3:]
    
    return output

def html_select_options(options, selected=None):
    return ['<option ' + ('selected' if option == selected else '') + '>' + option + '</option>' for option in options]

def groups(db, linkpath):
    groups_by_parent = {'root': []}
    for group in db.groups.find({'private': {'$ne': True}}):
        if not 'parent_group' in group:
            group['parent_group'] = 'root'

        for gid in group['parent_group'], group['_id']:
            if gid not in groups_by_parent:
                groups_by_parent[gid] = []

        groups_by_parent[group['parent_group']] += [group]

    def do_subgroups(gid): return ['<ul>'] + [item for sublist in list(map(do_group, groups_by_parent[gid])) for item in sublist] + ['</ul>']
    def do_group(g): return ['<li><a style="color:inherit;text-decoration:none" href="' + linkpath + str(g['_id']) + '">', esc(g['name']), '</a>'] + do_subgroups(g['_id']) + ['</li>']
    output = do_subgroups('root')
    
    return output

def group_breadcrumbs(group_ids, group_names, include_self=False):
    def link(gid): return '<a href="/groups/' + str(gid) + '">' + esc(group_names[gid]) + '</a>'

    crumbs = [link(gid) + ' &#x2192;' for gid in group_ids[1:]]
    crumbs.reverse()
    if include_self: crumbs += [link(group_ids[0])]
        
    return crumbs

def showgroup(db, item, show_member_actions=False, show_admin_actions=False):
    subgroups = db.groups.find({'parent_group': item['_id']})
    
    output = ['<br><small><a href="/groups">', esc(_('Groups')), '</a> &#x2192;']
    output += group_breadcrumbs(*walk_parent_groups(db, item))
    output += ['</small><h1 style="margin:0">', esc(item['name'])]
    if show_admin_actions:
        output += ['<span class=admin_action_toggle onclick=\'document.body.className="show_admin_actions"; document.querySelector("[name=group_description]").innerText=this.parentNode.nextElementSibling.innerText; document.querySelector("[name=group_name]").value=this.parentNode.innerText; this.parentNode.style.display="none"; this.parentNode.nextElementSibling.style.display="none";\'>⚙</span>']
    output += ['</h1>']
    output += ['<p>', esc(item['description']), '</p>']
    if show_admin_actions:
        output += ['<form method=post class=admin_action style="margin-left:-3px;"><h1 style="margin-top:0"><input name=group_name style="border-left:3px solid yellowgreen;width:100%;"></h1><textarea name=group_description style="border:0;border-left:3px solid yellowgreen;background:transparent;width:100%;height:4em;"></textarea><br><button class=admin_action>Set description and name</button></form>']
    
    if (show_member_actions or show_admin_actions) and item['pending_memberships']:
        output += ['<form method=post style="padding: 2em; background-color: greenyellow; color: black;"><h2>',
                   esc(_('The following new members are awaiting approval by an existing member:')), '</h2>']
        for uid in item['pending_memberships']:
            output += ['<br>']
            if show_admin_actions: output += [' <button name=cancelpendingmembership class="destructive visible_admin_action" value=' + str(uid) + '>⚙ Cancel request</button>']
            output += [esc(dbcacheget(db, 'people', uid, ['name'])['name'])]
            if show_member_actions: output += [' <button name=approvemember value=' + str(uid) + '>' + esc(_('Grant access')) + '</button>']
        output += ['</form>']

    output += ['<p><a href="/events?group=' + str(item['_id']) + '">', esc(_('Events')), '</a><br><a href="/threads?group=' + str(item['_id']) + '">', esc(_('Threads')), '</a><br><a href="/pages?group=' + str(item['_id']) + '">', esc(_('Pages')), '</a></p>']

    if subgroups.count() > 0:
        output += ['<h2>', esc(_('Subgroups:')), '</h2>']
        output += ['<a href="' + str(g['_id']) + '">' + esc(g['name']) + '</a><br>' for g in subgroups]
    if show_admin_actions:
        output += ['<button type=button class=admin_action onclick="window.location.href=this.dataset.action" data-action="/newgroups?parent_group=' + str(item['_id']) + '">Create subgroup...</button><br class=admin_action>']
        output += ['<button type=button class=admin_action onclick="window.location.href=this.dataset.action" data-action="/reparent_group/' + str(item['_id']) + '/">Reposition group...</button>']

    output += ['<h2>', esc(_('Members:')), '</h2>']
    for member in db.people.find({'groups': item['_id']}):
        if show_admin_actions:
            output += ['<button type=button class="admin_action semidestructive" onclick="window.location.href=this.dataset.action" data-action="/remove_users_from_group?group='+str(item['_id'])+'&amp;users=' + str(member['_id']) + '">-</button>']
        output += ['<a href="/people/' + str(member['_id']) + '">' + esc(member['name']) + '</a><br>']

    return output

def showuser(db, user, own_view=False, threads_to_list=None, editdescription=False, show_admin_actions=False):
    output = ['<h1>', esc(user['name']), show_admin_actions * '<span class=admin_action_toggle onclick=\'document.body.className="show_admin_actions";\'>⚙</span>', '</h1>']
        
    if own_view:
        if user['description'] == '' or editdescription:
            output += ['<form method=post action="/people/' + str(user['_id']) + '"><textarea style="width:100%;height:6em;" name=description>', esc(user['description']), '</textarea><button>', esc(_('Set')), '</button></form>']
        else:
            output += [esc(user['description'])]

        if not editdescription:
            output += ['<p>', ((user['description'] != '') * ('<a href="/people/changedescription">' + esc(_('Change description')) + '</a><br>')),
                       '<a href="/usersettings">Interface lingua ändern</a><br>',
                       '<a href="/changepassword">' + esc(_('Change password')) + '</a></p>']
    else:
        output += [esc(user['description'])]
        output += ['<p><a href="/messages/user/' + esc(urlesc(user['name'])) + '">' + esc(_('Communicate')) + '</a></p>']

    groups = db.groups.find({'_id': {'$in': user['groups']}, 'private':{'$ne':True}})
    output += ['<h2>', esc(_('Groups:')), '</h2>']
    output += [show_admin_actions*('<button class="admin_action semidestructive" type=button onclick="window.location.href=this.dataset.action" data-action="/remove_users_from_group?group='+str(group['_id'])+'&amp;users=' + str(user['_id']) + '">-</button> ')
               + '<a href="/groups/' + str(group['_id']) + '">' + esc(group['name']) + '</a><br>' for group in groups]
    output += [show_admin_actions*('<form method=post action="/usersadmin"><input type=hidden name=mode value=add_to_group><input type=hidden name=user_selected_'+str(user['_id'])+' value=foo><button class=admin_action>+</button></form>')]
    
    if threads_to_list is None:
        output += ['<p><a href="/people/' + str(user['_id']) + '/threads">' + esc(_('Posts')) + '</a></p>']
    else:
        output += ['<h2>', esc(_('Posts:')) , '</h2>']
        if threads_to_list == []:
            output += [esc(_('(None.)'))]
        else:
            for item in threads_to_list:
                output += listthread(db, item)
    
    return output

def urlesc(text):
    return text.replace(' ', '%20')#FIXME more
def http_request(host, path):
    import ssl, http.client
    req = http.client.HTTPSConnection(host, timeout=2, context=ssl.create_default_context())
    req.request('POST', path)
    res = req.getresponse()
    return res.status, res.read()
def comms(db, currentuser, decrypter, fucking_webkit=False):
    unique_other_users = set(db.messages.find({'to': currentuser['_id']}).distinct('from') + db.messages.find({'from': currentuser['_id']}).distinct('to'))
    parts = [[], []] #the ones with unreads in the first, the ones without in the second
    datalist = []
    for otheruserref in unique_other_users:
        message = db.messages.find({'$or': [{'from': currentuser['_id'], 'to': otheruserref}, {'to': currentuser['_id'], 'from': otheruserref}, ]}).sort('_id', -1)
        message = message[0]

        if type(otheruserref) is str:
            otheruser = currentuser['remote_contacts'][otheruserref]
        else:
            otheruser = dbcacheget(db, 'people', otheruserref, ['name'])
        names = {otheruser['_id']: otheruser['name'], currentuser['_id']: esc(_('Me'))}

        msgcount = unreadcount(db, currentuser, otheruser)
        part = []
        part += ['<a style="text-decoration:none" href="/messages/user/' + esc(urlesc(otheruser['name'])) + '"><b>' + esc(otheruser['name']) + '</b>']
        if msgcount: part += ['<big style="font-size:1.6em; color:green;">' + ('🐢' * msgcount) + '</big>']
        part += showmessage(db, currentuser, decrypter, message, names, False)
        part += ['</a><br><br>']
        parts[0 if msgcount else 1] += [(message['_id'].generation_time, part)]
        datalist += ['<option id="useroption_' + esc(otheruser['name'].lower().replace(' ', '_')) + '">' + esc(otheruser['name'])]

    output = ['<br><div id=usersearch style="display:none"><input type=search list=users autofocus placeholder="' + esc(_('search by name')) + '" onkeydown=\'this.dataset.inhibit_jump_once=(event.keyCode>123||(event.keyCode>44&amp;&amp;event.keyCode<112)||event.keyCode==32||(event.keyCode==8&amp;&amp;this.value.length>0))?"true":"false";if(event.keyCode==13||event.keyCode==39)this.oninput();\' oninput=\'if(this.dataset.inhibit_jump_once=="true"){this.dataset.inhibit_jump_once="false";return;} usermatch=document.getElementById("useroption_" + this.value.toLowerCase().trim().replace(/ /g, "_")); if(usermatch)window.location.href="/messages/user/"+usermatch.value;\'><br><br></div><a id=newlink href="/people">' + esc(_('New')) + '</a><br><br><br><script>document.getElementById("usersearch").style.display="block";document.getElementById("newlink").href="/messages/new";</script><datalist id=users>'] + datalist + ['</datalist>']
    if fucking_webkit: output = ['<br><select onchange=\'window.location.href="/messages/user/"+this.value;\'><option selected>'] + datalist + ['</select><br><br><a href="/people">Ny</a><br><br><br>']#webkit no support datalist

    for someparts in parts:
        for part in (sorted(someparts, key=lambda x: x[0], reverse=True)):
            output += part[1]

    return output

def comms_with_user(db, otheruser, currentuser, decrypter):
    messages = db.messages.find({'$or': [{'to': otheruser['_id'], 'from': currentuser['_id']}, {'from': otheruser['_id'], 'to': currentuser['_id']}]}).sort('_id')

    names = {party['_id']: party['name'] for party in [otheruser, currentuser]}
    output = ['<h1>', esc(otheruser['name']), '</h1>']
    message = None
    for message in messages:
        output += showmessage(db, currentuser, decrypter, message, names, False) + ['<br>']

    if message:
        output += ['<script id=news_insert_marker>fetch_news.position_info="' + str(otheruser['_id']) + '|' + str(message['_id']) + '";</script>']
    output += ['<form method=post><textarea oninput="this.value=this.value.replace(/\\n/g, \'\');" autofocus style="width:100%;height:10em;" name=msg></textarea><button>Send</button></form>']
    return output

def showmessage(db, currentuser, decrypter, message, names, show_recipient_name=True):
    if message['to'] == currentuser['_id'] and not 'read' in message:
        message['read'] = True
        db.messages.replace_one({'_id': message['_id']}, message)
    
    try:
        msgkey = decrypter.decrypt(message['keys'][str(currentuser['_id'])])
    except ValueError:
        msgkey = b'00000000000000010000000000000001'
        
    def _OLDMSGFORMATCOMPATdecrypt(iv_and_key, encrypted_msg): aes_cipher = AES.new(iv_and_key[AES.block_size:], AES.MODE_CFB, iv_and_key[:AES.block_size]); return aes_cipher.decrypt(encrypted_msg).decode()
    try:
        msg = _OLDMSGFORMATCOMPATdecrypt(msgkey, message['msg']) #XXX change this to use encrypt()/decrypt() next time we break format compat anyway
    except ValueError:
        msg = '[DECRYPTION FAILED] ' + (repr(message['msg']))

    fancy_trick = hashlib.md5((str(message['to']) + str(message['from'])).encode()).hexdigest()[:6]
    output = ['<article class=msg style="border-color: #' + fancy_trick + ';">']
    if msg.startswith('/me '):
        output += ['<i>* ' + esc(names[message['from']]) + ' ' + esc(msg[4:]) + '</i>']
    else:
        output += [esc(names[message['from']]) + ': ' + esc(msg)]
    output += ['<br><small>', formatdate(message['_id'].generation_time), '</small></article>']
    return output

def group_view_helper(db, permitted_groups, selected_group):
    if selected_group is None:
        groupids = permitted_groups
    else:
        assert selected_group in permitted_groups
        groupids = [selected_group]
    
    groups = db.groups.find({'_id': {'$in': permitted_groups}}).sort([('name', 1)])
    selectorhtml = ['<select name=group onchange="this.form.submit()"><option value="">' + esc(_('All groups')) + '</option>']
    selectorhtml += ['<option value=' + str(group['_id']) + (' selected' if group['_id'] == selected_group else '')
                     + (' style="font-style:italic"' if 'private' in group else '') + '>' + esc(group['name']) + '</option>' for group in groups]
    selectorhtml += ['</select><noscript><button>' , esc(_('Show')), '</button></noscript>']
    
    return (groupids, selectorhtml)

def threads(db, permitted_groups, encrypted_groupkeys, decrypter, selected_group=None, highlightid=None):
    groupids, groupselector = group_view_helper(db, permitted_groups, selected_group)

    output = ['<br><form action="/threads">'] + groupselector + ['</form><br><a href="/threads/new">' + esc(_('New')) + '</a><br><br>']

    groupkeys = {}
    for item in db.threads.find({'group': {'$in': groupids}}).sort([('lastupdate', -1)]):
        if not item['group'] in groupkeys:
            groupkeys[item['group']] = loadgroupkey(item['group'], encrypted_groupkeys, decrypter); #output += ['<hr>loaded groupkey for ' + repr(item['group']) + '<hr>']
        decrypt_values(item, ['title'], groupkeys[item['group']])
        output += listthread(db, item, highlightid)

    return output

def listthread(db, item, highlightid=None):
    author = dbcacheget(db, 'people', item['messages'][0]['author'], ['name'])
    lastauthor = dbcacheget(db, 'people', item['messages'][-1]['author'], ['name'])
    group = dbcacheget(db, 'groups', item['group'], ['name', 'private'])

    attributes = '' if item['_id'] != highlightid else ' class=highlight'
    output = ['<br><div' + attributes + '><a href="/threads/' + str(item['_id']) + '">', esc(item['title']),
               '</a><br><small style="display:inline-block;margin-left:1em">',
               ('private' not in group) * (esc(_('by')) + ' <a href="/people/' + str(lastauthor['_id']) + '">' + esc(author['name']) + '</a>'),
               esc(_('in')), ' <a href="/groups/' + str(group['_id']) + '">' + esc(group['name']) + '</a> ', formatdate(item['messages'][0]['_id'].generation_time, False),
               '<br>', esc(_('newest message')),
               ('private' not in group) * (esc(_('by')) + ' <a href="/people/' + str(lastauthor['_id']) + '">' + esc(lastauthor['name']) + '</a> '),
               formatdate(item['messages'][-1]['_id'].generation_time, True, False), '</small></div>']
    return output

def events(db, permitted_groups, encrypted_groupkeys, decrypter, selected_group=None, highlightid=None, show_old=False):
    groupids, groupselector = group_view_helper(db, permitted_groups, selected_group)
    output = ['<br><form action="/events">'] + groupselector + ['</form><br><a href="/events/new">' + esc(_('New')) + '</a><br><br>']
    
    groupkeys = {}

    if show_old:
        for item in db.events.find({'group': {'$in': groupids}}).sort([('end', 1)]):
            if not item['group'] in groupkeys:
                groupkeys[item['group']] = loadgroupkey(item['group'], encrypted_groupkeys, decrypter)
            decrypt_values(item, ['title'], groupkeys[item['group']])
            output += listevent(db, item, highlightid)
    else:
        steadynow = datetime.now()

        items = db.events.find({'group': {'$in': groupids}, 'start': {'$lte': steadynow}, 'end': {'$gte': steadynow}}).sort([('end', 1)])
        if items.count() > 0:
            output += ['<section id=happeningnow><h1>', esc(_('HAPPENING RIGHT NOW:')), '</h1>']
            for item in items:
                if not item['group'] in groupkeys:
                    groupkeys[item['group']] = loadgroupkey(item['group'], encrypted_groupkeys, decrypter)
                decrypt_values(item, ['title'], groupkeys[item['group']])
                output += listevent(db, item, highlightid)
            output += ['</section>']

        output += ['<section>']
        for item in db.events.find({'group': {'$in': groupids}, 'start': {'$gt': steadynow}}).sort([('start', 1)]):
            if not item['group'] in groupkeys:
                groupkeys[item['group']] = loadgroupkey(item['group'], encrypted_groupkeys, decrypter)
            decrypt_values(item, ['title'], groupkeys[item['group']])
            output += listevent(db, item, highlightid)
        output += ['</section>']

        output += ['<br><p style="font-size:smaller"><a href="/events/all' + ('' if selected_group is None else '?group=' + str(selected_group)) + '">' + esc(_('Show all events (including past)')) + '</a></p>']

    return output

def listevent(db, item, highlightid=None):
    group = dbcacheget(db, 'groups', item['group'], ['name'])
    attributes = '' if item['_id'] != highlightid else ' class=highlight'
    output = ['<br><div' + attributes + '><a href="/events/' + str(item['_id']) + '">' + esc(item['title']) + '</a>',
               esc(_('(Vote)')) if item['mode'] == 'vote' else '',
               '<br><small style="display:inline-block;margin-left:1em">',
               esc(_('in')) + '<a href="/groups/' + str(group['_id']) +'">', esc(group['name']), '</a>',
               '<br>', formatdate(item['start'], True, False),
               (esc(_('until')) + ' ' + formatdate(item['end'], True, False) if item['start'].date() != item['end'].date() else
                   (esc(_('until')) + ' ' + formatdate(item['end'], -1, False) if item['start'] != item['end'] else '')), '</small></div>']

    return output

def pages(db, permitted_groups, encrypted_groupkeys, decrypter, selected_group=None, highlightid=None):
    groupids, groupselector = group_view_helper(db, permitted_groups, selected_group)

    output = ['<br><form action="/pages">'] + groupselector + ['</form><br>']
    if selected_group:
        output += ['<a href="/pages/' + str(selected_group) + '/Home">Home</a><br><br>']
    else:
        output += ['<a href="/pages/new">' + esc(_('New')) + '</a><br><br>']

    groupkeys = {}

    for item in db.pages.find({'group': {'$in': groupids}}).sort([('revisions._id', -1)]):
        if not item['group'] in groupkeys:
            groupkeys[item['group']] = loadgroupkey(item['group'], encrypted_groupkeys, decrypter); #output += ['<hr>loaded groupkey for ' + repr(item['group']) + '<hr>']
        decrypt_values(item, ['title'], groupkeys[item['group']])
        output += listpage(db, item, highlightid)

    return output

def listpage(db, item, highlightid=None):
    editor = dbcacheget(db, 'people', item['revisions'][-1]['editor'], ['name'])
    group = dbcacheget(db, 'groups', item['group'], ['name', 'private'])

    attributes = '' if item['_id'] != highlightid else ' class=highlight'
    output = ['<br><div' + attributes + '><a href="/pages/' + str(group['_id']) + '/' + esc(item['title']) + '">', esc(item['title']),
              '</a><br><small style="display:inline-block;margin-left:1em">',
              esc(_('in')), '<a href="/groups/' + str(group['_id']) + '">' + esc(group['name']) + '</a><br>',
              'last edited', formatdate(item['revisions'][-1]['_id'].generation_time, True, False),
              ('private' not in group) * (esc(_('by')) + ' <a href="/people/' + str(editor['_id']) + '">' + esc(editor['name']) + '</a> '),
              '</small></div>']
    return output

def group_insert_helper(db, permitted_groups):
    groups = db.groups.find({'_id': {'$in': permitted_groups}})
    if groups.count() == 0:
        return None
    output = ['<label>', esc(_('Group:')), '<select name=group required><option value="">']
    output += ['<option value=' + str(group['_id']) + '>' + esc(group['name']) for group in groups]
    output += ['</select></label><br>']

    return output

def showthread(db, item, permitted_groups=[]):
    output = ['<h1>', esc(item['title']), '</h1>']

    if '_id' in item:
        group = dbcacheget(db, 'groups', item['group'], ['name'])
        output += ['<p>', esc(_('Group:')), ' <a href="/groups/' + str(item['group']) + '">', esc(group['name']), '</a></p>']

        for message in item['messages']:
            output += showthreadmessage(db, item['_id'], message)
        output += ['<script id=news_insert_marker>fetch_news.position_info="' + str(message['_id']) + '";</script>']

    output += ['<form method=post id=form action="#form">']
    if not '_id' in item:
        output += ['<h1>' + esc(_('New thread')) + '</h1>']

        if 'event' in item:
            output += ['<input type=hidden name=event value=' + str(item['event']) + '>', esc(_('The thread will be attached to')), ' <a href="/events/' + str(item['event']) + '">' + esc(_('this event')) + '</a>.<br><br>']
        else:
            output += [esc(_('Title:')), '<input required autofocus size=40 maxlength=' + str(MAXLEN['title']) + ' name=title><br>']
            grouplist = group_insert_helper(db, permitted_groups)
            if not grouplist:
                return ['<p>You need to be a member of a group to create a thread.</p>']
            output += grouplist + ['<br>']

    output += ['<textarea rows=8 cols=70 style="max-width:97%" name=msghtml class=formatting></textarea><br><button>', esc(_('Submit')), '</button>']
    if '_id' in item:
        output += ['<p><a href="/events/new?thread=' + str(item['_id']) + '">' + esc(_('Create event')) + '</a></p>']
    output += ['</form>']
    
    return output

def showthreadmessage(db, thread_id, message):
    author = dbcacheget(db, 'people', message['author'], ['name'])
    fancy_trick = hashlib.md5((str(thread_id)[:4] + author['name']).encode()).hexdigest()[:6]

    messagetextwrapper = ('', '')
    if 'event_id' in message:
        messagetextwrapper = ('<a href="/events/' + str(message['event_id']) + '">', '</a>')

    return ['<article class=threadmsg style="border-color: #' + fancy_trick + ';">',
               '<small>', formatdate(message['_id'].generation_time), '</small><br>',
               '<a href="/people/' + str(message['author']) + '">' + esc(author['name']) + '</a>:<br>',
               messagetextwrapper[0], message['html'], messagetextwrapper[1],
               '</article><br>']

def showevent(db, item, permitted_groups=[], edit_existing=False, show_edit_link=False):
    opiniontitles = {-1: _('is opposed'), 0: _('is not opposed'), 1: _('is in favor')}

    output = []
    if '_id' not in item or edit_existing:
        output += ['<form method=post>']
        if edit_existing:
            output += ['<h1>', esc(item['title']), '</h1>']
        else:
            output += ['<h1>', esc(_('New event')), '</h1>']

        output += ['<label>', esc(_('Title:')), '<br><input required size=40 maxlength=' + str(MAXLEN['title']) + ' value="' + esc(item['title']) + '" name=title></label><br><br><label>',
                    esc(_('Description:')), '<br><textarea class=formatting name=descriptionhtml rows=6 cols=60>' + esc(item['descriptionhtml']) + '</textarea></label><br><br><label>',
                    esc(_('Begins:')), '<br><input name=start max="9000-01-01T00:00:00" type=datetime-local required value="' + str(item['start']).replace(' ', 'T') + '" onchange="var endfield=document.querySelector(\'input[name=end]\');endfield.min=this.value;endfield.value=this.value;"></label><br><label>',
                    esc(_('Ends:')), '<br><input name=end max="9000-01-01T00:00:00" type=datetime-local value="' + str(item['end']).replace(' ', 'T') + '"></label><br><br>']

        if edit_existing:
            output += ['<br><button>', esc(_('Update')), '</button>']
        else:
            output += [esc(_('Type:')), '<br><label><input type=radio name=mode value=event' + (' checked' * (item['mode']!='vote')) + '>', esc(_('Event')),
                        '</label><br><label><input type=radio name=mode value=vote' + (' checked' * (item['mode']=='vote')) + '>', esc(_('Vote')),  '</label><br><br>']
            if 'thread' in item:
                output += ['<input type=hidden name=thread value=' + str(item['thread']) + '>' + esc(_('The event will be connected to')) + ' <a href="/threads/' + str(item['thread']) + '">' + esc(_('this thread')) + '</a>.<br>']
            elif 'group' in item:
                output += ['<input type=hidden name=group value=' + str(item['group']) + '>']
            else:
                grouplist = group_insert_helper(db, permitted_groups)
                if not grouplist:
                    return ['<p>You need to be a member of a group to create an event.</p>']
                output += grouplist
            output += ['<br><button>', esc(_('Create')), '</button>']

        output += ['</form>']
    else:
        author = dbcacheget(db, 'people', item['author'], ['name'])
        group = dbcacheget(db, 'groups', item['group'], ['name'])

        output += ['<h2>', esc(_('Vote')) if item['mode'] == 'vote' else esc(_('Event')), '</h2>']
        output += ['<h1>', esc(item['title'])]
        if show_edit_link:
            output += ['[<a href="' + str(item['_id']) + '/edit">', esc(_('edit')), '</a>]']
        output += ['</h1>', item['descriptionhtml'], '<br><br>', esc(_('Begins:')), formatdate(item['start'], True, False), '<br>', esc(_('Ends:')), formatdate(item['end'], True, False), '<br><br>']
        output += [esc(_('Created by')), ' <a href="/people/' + str(author['_id']) + '">' + esc(author['name']) + '</a> ', formatdate(item['_id'].generation_time, True, False)]
        output += ['<br>', esc(_('Group:')), ' <a href="/groups/' + str(item['group']) + '">', esc(group['name']), '</a><br>']
        if 'thread' in item:
            output += [esc(_('Thread:')), ' <a href="/threads/' + str(item['thread']) + '">', esc(item['thread_TITLE']), '</a><br><br>']
        else:
            output += ['<a href="/threads/new?event=' + str(item['_id']) + '">', esc(_('Create a thread to discuss this event')), '</a><br><br>']

        if item['mode'] == 'vote':
            has_begun = item['start'] < datetime.now()
            is_over = item['end'] < datetime.now()
            
            if has_begun:
                if not is_over:
                    output += ['<form method=post>', esc(_('Your opinion:')), ' <select name=opinion><option value="+1">' + esc(_('In favor of the proposal')) + '</option><option value="00" selected>' + esc(_('Not opposed to the proposal')) + '</option><option value="-1">' + esc(_('Opposed to the proposal')) + '</option></select><br><label>', esc(_('Comment:')), ' <input name=opinioncomment></label><br><button>', esc(_('Set')) , '</button></form>']
                nays = 0
                opinions = {-1: [], 0: [], 1: []}
                #XXX vi skal ikke først hive alle members ud og derefter hive dem ud en efter en
                #- men skal vi først hive dem alle ud og så iterate over DEM i stedet for item['opinions'],
                #(så vi har deres navn når vi skal bruge det), eller skal vi IKKE hive dem ud først
                #og i stedet høste participant_ids for bagefter at bede db om dem der IKKE er dem?
                #XXX er denne kommentar stadig relevant efter dbcacheget?
                members = db.people.find({'groups': {'$in': [group['_id']]}}) #XXX $in er overflødig, bare 'groups': group['_id'] (tror jeg)
                non_participant_ids = [member['_id'] for member in members]

                for opinionkey in item['opinions']:
                    ballot_vote = int(item['opinions'][opinionkey][:2])
                    ballot_comment =  item['opinions'][opinionkey][3:]
                    if ballot_vote == -1:
                        nays += 1
                    opinions[ballot_vote] += ['<br>', esc(dbcacheget(db, 'people', ObjectId(opinionkey), ['name'])['name']), esc(opiniontitles[ballot_vote]), '' if ballot_comment == '' else '<i>(' + esc(ballot_comment) + ')</i>']
                    non_participant_ids.remove(ObjectId(opinionkey))

                if len(item['opinions']) > 1:
                    output += ['<br><br><span title="' + str(nays) + ' opposed out of ' + str(len(item['opinions'])) + ' opinions">', str(round(100 - (nays / len(item['opinions'])) * 100, 1)) + '% ', esc(_('consensus among participants')), '</span>']
                    output += ['<br><span title="' + str(nays) + ' opposed out of ' + str(members.count()) + ' members">', str(round(100 - (nays / members.count()) * 100, 1)) + '% ', esc(_('consensus among the whole group')), '</span><br>']
                output += opinions[-1]
                output += ['<br>']
                output += opinions[0]
                output += ['<br>']
                output += opinions[1]
                output += ['<br>']
                output += ['<br>' + esc(dbcacheget(db, 'people', id, ['name'])['name']) + ' ' + esc(_('has not participated')) for id in non_participant_ids]
            
            if is_over:
                output += ['<br><br><form method=post action="/events/new"><input type=hidden name=template_event_id value="' + str(item['_id']) + '"><input type=submit value="' + esc(_('Reboot proposal')) + '"></form>']
    return output

def showpage(db, item, permitted_groups=[]):
    output = ['<form method=post action="', '/pages/new' if '_id' not in item else esc(item['title']), #specifying title as action is useful when renaming pages
        '" onsubmit=\'let a = document.querySelector("article"); if (a.isContentEditable) document.getElementById("html").value = a.innerHTML;\'>',
        '<h1><input required size=40 maxlength=' + str(MAXLEN['title']) + ' name=title placeholder="' + esc(_('Title')) + '" value="' + esc(item['title']) + '"></h1>']

    if 'group' in item:
        group = dbcacheget(db, 'groups', item['group'], ['name'])
        output += ['<p>', esc(_('Group:')), ' <a href="/groups/' + str(item['group']) + '">', esc(group['name']), '</a></p><input type=hidden name=group value=' + str(item['group']) + '>']
    else:
        grouplist = group_insert_helper(db, permitted_groups)
        if not grouplist:
            return ['<p>You need to be a member of a group to create a page.</p>']
        output += grouplist + ['<br>']

    revision = item['revisions'].pop()
    
    def wikilinks(text):
        for sep in [' ', '<br>']:
            text = _wikilinks(text, sep)
        return text
    def _wikilinks(text, separator): return separator.join(['<a href="' + esc(x) + '">' + esc(x) + '</a>' if x.isalnum() and x[0].isupper() and x[1:] != x[1:].lower() else x for x in text.split(separator)])

    output += ['<article ondblclick=\'delink(this); document.querySelector(".edit").style.display="unset"; this.contentEditable=true; this.focus();\' style="min-height: 4em">',
        wikilinks(revision['html']), '''</article><script>setTimeout('let a=document.querySelector("article"); if (a.innerText.trim()=="") a.ondblclick()', 1); function delink(elm) {for (var lnk of elm.querySelectorAll('a')) {lnk.parentNode.insertBefore(document.createTextNode(lnk.getAttribute('href')), lnk); lnk.parentNode.removeChild(lnk);}}</script>''',
        '<input id=html type=hidden name=html value="' + esc(revision['html']) + '">',
        '<div class=edit style="display:none"><button>', esc(_('Save') if '_id' in item else _('Create')),
        '</button><p><small>You create new pages by stringing words together LikeThis and it becomes a link.</small></p></div><br><br><hr></form>']

    while item['revisions']:
        revision = item['revisions'].pop()
        editor = dbcacheget(db, 'people', revision['editor'], ['name'])
        output += [
            '<details><summary>Previous revision from', formatdate(revision['_id'].generation_time),
            ('private' not in group) * (esc(_('by')) + ' <a href="/people/' + str(editor['_id']) + '">' + esc(editor['name']) + '</a> '),
            '</summary>',
            revision['html'],
            '</details>'
        ]
    
    return output


### | | |                 | | |
### | | |                 | | |
### | | | here be dragons | | |
### | | |                 | | |
### V V V                 V V V
### ============================

def notify_group(env, db, item, title, url, text, originating_user_name):
    notifications = []
    group = db.groups.find_one(item['group'])
    members = db.people.find({'groups': {'$in': [group['_id']]}})
    
    mailrcpts = []
    for member in members:
        if 'email' in member and len(member['email']) > 2:
            mailrcpts += [member['email']]
        if 'evilempireid' in member:
            notifications += prepare_evilempire_notification(env, member['evilempireid'], url, text + title, 'Af ' + originating_user_name + ' i ' + group['name'], group['name'] + ": " + text + title, 'imp.wav')
        if 'tlf' in member and len(member['tlf']) > 2:
            notifications += prepare_sms_notification(env, member['tlf'], url + '\n' + group['name'] + ' - ' + text + title)

    if mailrcpts:
        message = [text, title, '\nI gruppe: ', group['name'], '\nOprettet af ', originating_user_name, '\n\nhttps://', url]
        mailnotif = {'type': 'email'}
        mailnotif['msg'] = ''.join(message)
        mailnotif['subject'] = '[' + group['name'] + '] ' + text + title
        mailnotif['recipient'] = ('BCC', ', '.join(mailrcpts))
        notifications += [mailnotif]

    send_notifications(env, db, notifications)

def notify_user(env, db, target, url, text, originating_user_name):
    notifications = []

    if 'evilempireid' in target:
        notifications += prepare_evilempire_notification(env, target['evilempireid'], url, originating_user_name + ' skriver:', text, originating_user_name + ': ' + text)

    if 'tlf' in target:
        notifications += prepare_sms_notification(env, target['tlf'], url + '\nBesked fra ' + originating_user_name + ': ' + text)
    
    if 'email' in target and len(target['email']) > 2:
        message = ['Ny besked fra ', originating_user_name, ':\n\n', text, '\n\nhttps://', url]

        notification = {'type': 'email'}
        notification['msg'] = ''.join(message)
        notification['subject'] = 'Ny besked fra ' + originating_user_name
        notification['recipient'] = ('To', target['email'])
        notifications += [notification]

    send_notifications(env, db, notifications)

def prepare_evilempire_notification(env, target_evilempireid, url, title, text, oneliner, sound="newmsg.mp3"):
    if not 'EvilEmpireKey' in env:
        return []

    body = '{"to":"' + target_evilempireid + '", "data": {"host": "' + env['HTTP_HOST'] + '", "url": "' + url + '", "oneliner":"' + esc(oneliner) + '"}, "notification": {"click_action": "firebase_notify", "body":"' + esc(text) + '", "title": "' + esc(title) + '", "sound": "' + sound + '"}}'
    return [{'type': 'evilempire', 'body': body}]

def prepare_sms_notification(env, target_number, text):
    return [{'type': 'sms', 'num': target_number, 'msg': text}]

def send_notifications(env, db, notifications):
    if not notifications:
        return

    import urllib.request, urllib.error

    for notif in notifications:
        db.notify_todo.insert_one(notif)

    try:
        req = urllib.request.Request('https://' + env['HTTP_HOST'] + '/_NOTIFY_PING')
        output = urllib.request.urlopen(req).read().decode('utf8', 'ignore')
    except urllib.error.HTTPError:
        db.adminlog.insert_one({'FEJL_I_NOTIFICATIONS':repr(notifications),'now':repr(datetime.now())})

def release_carrier_pidgeons(env, db, mailconfig):
    import smtplib
    from email.mime.text import MIMEText
    from email.header import Header
    import urllib.request

    def send_mail(notification):
        msg = MIMEText(notification['msg'])
        msg['Subject'] = Header(notification['subject'], 'utf-8')
        msg['From'] = mailconfig['mailfrom']
        msg[notification['recipient'][0]] = notification['recipient'][1]
        s = smtplib.SMTP(mailconfig['smtpserver'])
        s.send_message(msg)
        s.quit()

    def send_sms(notification):
        pymongo.MongoClient()['smssendingservice']['outbox'].insert_one(notification)
        req = urllib.request.Request('https://' + env['HTTP_HOST'] + '/sb')
        output = urllib.request.urlopen(req).read().decode('utf8', 'ignore')

    def send_skynet(notification):
        req = urllib.request.Request('https://fcm.googleapis.com/fcm/send', notification['body'].encode('utf-8'))
        req.add_header('Authorization', env['EvilEmpireKey'])
        req.add_header('Content-Type', 'application/json')
        responseData = urllib.request.urlopen(req).read().decode('utf8', 'ignore')

    one = db.notify_todo.find_one_and_delete({})
    while one:
        if one['type'] == 'email':
            send_mail(one)
        elif one['type'] == 'evilempire':
            send_skynet(one)
        elif one['type'] == 'sms':
            send_sms(one)
        one = db.notify_todo.find_one_and_delete({})

