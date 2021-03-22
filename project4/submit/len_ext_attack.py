from pymd5 import md5, padding
import httplib, urlparse, sys
from urllib import quote

if len(sys.argv) != 2:
    print "Usage: python len_ext_attack.py <url>"
    sys.exit(1)

# get url from input: http://cs526-s18.cs.purdue.edu/project4/api?token=d6613c382dbb78b5592091e08f6f41fe&user=nadiah&command1=ListSquirrels&command2=NoOp
url = sys.argv[1]
parsedUrl = urlparse.urlparse(url)
query = parsedUrl.query
querylist = query.split("&")
token = querylist[0].split("=")[1]

user = query.replace(querylist[0], '')# this string should be like '&user= ... '
user = user[1:]

# to construct a new message using token
length = (8 + len(user) + len(padding((len(user) + 8)*8)))*8
h = md5(state=token.decode("hex"), count=length)
extension = "&command3=UnlockAllSafes"
h.update(extension)
token_new = h.hexdigest()

# to construct the new url
pad = padding((8+len(user))*8)
query_new = "token=" + token_new + "&" + user + quote(pad) + extension
url_new = parsedUrl.path + "?" + query_new



conn = httplib.HTTPConnection(parsedUrl.hostname, parsedUrl.port)
conn.request("GET", url_new)
print conn.getresponse().read()