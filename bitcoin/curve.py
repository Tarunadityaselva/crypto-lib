from collections import namedtuple

# Curve parameters of secp256k1
FIELD_SIZE = 0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GROUP_ORDER = 0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SHANKS_CONSTANT = (GROUP_ORDER + 1) // 4

# Point on the curve
Point = namedtuple("Point", "x", "y")

def x_to_y(x):
    """Calculate y coordinate from x coordinate"""
    return pow(x, 3, FIELD_SIZE) + 7