import xml.etree.ElementTree as ET


def lookup(root, request):
    return root.find(request.args['path'])
