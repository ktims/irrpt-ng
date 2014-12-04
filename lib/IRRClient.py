import socket, logging, itertools, collections
from IPy import IP, IPSet

class RouteSet(collections.MutableSet):
    def __init__(self, routes=(), aggregate=True):
        if aggregate:
            self.ip4 = IPSet()
            self.ip6 = IPSet()
        else:
            self.ip4 = set()
            self.ip6 = set()

        if routes:
            for r in routes:
                self.add(r)

    def __len__(self):
        """
        IPy doesn't provide a len() for number of prefixes
        but that's really what we're interested in here, so override
        their semantics.
        """
        if isinstance(self.ip4, IPSet):
            return len(self.ip4.prefixes) + len(self.ip6.prefixes)
        else:
            return len(self.ip4) + len(self.ip6)

    def __iter__(self):
        return itertools.chain(self.ip4, self.ip6)

    def __contains__(self, item):
        return item in self.ip4 or item in self.ip6

    def add(self, item):
        ip = IP(item, make_net=True)
        if ip.version() == 4:
            self.ip4.add(ip)
        elif ip.version() == 6:
            self.ip6.add(ip)
    
    def discard(self, item):
        ip = IP(item, make_net=True)
        self.ip4.discard(ip)
        self.ip6.discard(ip)



class IRRClient:
    def __init__(self, host, port=43, cache=True, aggregate=True, ipv6=True):
        self.host = host
        self.port = port
        self.caching = cache
        self.aggregate = aggregate
        self.ipv6 = True
        
        self._cache = dict()
        """
        Two caches are contained here.
        - Integer keys point to RouteSet objects for origins
        - String keys point to RouteSet objects for route-sets
        """

        self._ascache = dict()
        "This cache stores as-set -> origin AS lists keyed by string as-set name"

        self.s = None
        self.f = None

        self.lastcommand = None

        self.log = logging.getLogger(self.__module__)

    def connect(self):
        sa = (self.host, self.port)
        try:
            self.log.debug('connecting to %s' % (repr(sa)))
            self.s = socket.create_connection(sa)
        except socket.error as msg:
            self.s.close()
            self.s = None
            self.log.error('connection error: %s' % (msg))

        if self.s is None:
            self.log.error('unable to connect to any nodes of %s:%d' % (sa))
            return False

        self.f = self.s.makefile()

        self._multi()
        self._identify()

        return self

    def _send(self, output):
        self.lastcommand = output.rstrip()

        try:
            self.s.sendall(output)
        except socket.error as msg:
            self.log.error('Unexpected write error: %s' % (msg))
            return False

        return True

    def _multi(self):
        self._send("!!\n")

        return True

    def _identify(self):
        self._send("!nirrpt-ng\n")
        self._response()

        return True

    def _readline(self):
        return self.f.readline()

    def _response(self):
        header = self._readline().rstrip()
        data = ""

        if header[0] == "C":
            return True
        elif header[0] == "D":
            self.log.warning('key not found - query: %s' % (self.lastcommand))
            return False
        elif header[0] == "E":
            return True
        elif header[0] == "F":
            self.log.warning('query failed: %s' % (header[1:]))
            return False

        if header[0] == "A":
            datalen = int(header[1:])
        else:
            self.log.error('parse error looking for data length')
            return False

        while len(data) < datalen:
            data = data + self._readline()

        if len(data) != datalen:
            self.log.error("data read doesn't match expected length")

        footer = self._readline()

        return data.rstrip()

    def set_sources(self, sources):
        self._send("!s-%s\n" % (sources))

        results = self._response()
        if not results:
            return False

        return results.split()

    def get_sources(self):
        self._send("!s-lc\n")
        results = self._response()
        if not results:
            return False

        return results

    def _is_cached(self, origin):
        return self.caching and origin in self._cache

    def _get_cache(self, key):
        if self.caching and key in self._cache:
            return self._cache[key]

        return False

    def _set_cache(self, key, routes):
        if self.caching:
            self._cache[key] = routes

    def get_routes_by_origin(self, origin):
        try:
            origin = int(origin)
        except:
            raise TypeError("origin must be convertable to integer")

        if self._is_cached(origin):
            return self._get_cache(origin)

        routes = RouteSet(aggregate=self.aggregate)

        self._send("!gAS%s\n" % (origin))
        response = self._response()

        if response:
            for r in response.split():
                routes.add(r)

        if self.ipv6:
            self._send("!6AS%s\n" % (origin))
            response = self._response()

            if response:
                for r in response.split():
                    routes.add(r)

        self._set_cache(origin, routes)
        return routes

    def get_data_by_set(self, s):
        if self._is_cached(s):
            return self._get_cache(s)
        self.log.debug("Fetching all routes for object %s" % (s))
        routes = RouteSet(aggregate=self.aggregate)

        self._send("!i%s,1\n" % (s))
        response = self._response()

        if not response:
            return (routes, ())

        response = response.upper()

        autnums = tuple(int(asn.lstrip("AS")) for asn in response.split())

        if not autnums:
            self.log.warning("Nothing returned for object %s" % (s))
            return (routes, ())

        obj_type = "as-set"
        if (':' in response or '.' in response) and 'AS' not in response:
            obj_type = "route-set"

        if obj_type == "route-set":
            "This is a route-set"
            self.log.debug("Response indicates this is a route-set object")
            for r in autnums:
                routes.add(r)

            if routes:
                self._set_cache(s, routes)
            self.log.debug("Retrieved %d routes from route-set" % (len(routes)))

        elif obj_type == "as-set":
            "This is an as-set"
            self.log.debug("Response indicates this is an as-set object")
            for asn in autnums:
                for r in self.get_routes_by_origin(asn):
                    if r:
                        routes.add(r)
            self.log.debug("Retrieved %d routes from %d ASNs" % (len(routes), len(autnums)))

        return (routes, autnums)

    def get_members_by_set(self, s, recursive=False):
        self.log.debug("Fetching members of set %s recursive(%s)" % (s, str(recursive)))

        if recursive:
            self._send("!i%s,1\n" % (s))
        else:
            self._send("!i%s\n" % (s))

        response = self._response()
        if not response:
            return False

        data = response.split()
        return tuple(set(data))
