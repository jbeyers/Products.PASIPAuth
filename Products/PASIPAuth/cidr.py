import socket

def cidr(address):
    try:
        x = socket.inet_aton(address)
    except:
        raise ValueError("%s is not a valid ip address" % address)
    x = (ord(x[0])<<24) + (ord(x[1])<<16) + (ord(x[2])<<8) + ord(x[3])
    return x

def in_cidr(address, net):
    """
    Takes two strings, the first an IP address, the second a network in
    CIDR format
    Returns True if the adress is in the network

    Example:
    >>> in_cidr('10.0.0.7', '10.0.0.0/29')
    True
    >>> in_cidr('10.0.0.8', '10.0.0.0/29')
    False
    >>> in_cidr('127.0.0.1', '127.0.0.1')
    True
    """

    print('Enter in_cidr with {} and {}'.format(address, net))
    mask = 0xFFFFFFFF
    components = net.split("/")
    print('Cpmponents: {}'.format(components))
    print('Cpmponents: len = {}'.format(len(components)))
    if len(components) > 1:
        print('Cpmponents: len = {}'.format(len(components)))
        mask = ~(0xFFFFFFFF >> int(components[1]))

    try:
        x = cidr(address)
    except Exception as err:
        print('Exception x in in_cidr: {}'.format(err))
        result = False

    try:
        y = cidr(components[0])
    except Exception as err:
        print('Exception y in in_cidr: {}'.format(err))
        result = False

    try:
        print('match {} to {}'.format(x, y))
        result = (x & mask) == y
    except Exception as err:
        print('Exception match in in_cidr: {}'.format(err))
        result = False

    return result

#if __name__ == '__main__':
#    print in_cidr('10.0.0.7', '10.0.0.0/29')
#    print in_cidr('10.0.0.8', '10.0.0.0/29')
#    print in_cidr('127.0.0.1', '127.0.0.1')
#    print in_cidr('10.0.0.20', '10.0.0.0/24')
