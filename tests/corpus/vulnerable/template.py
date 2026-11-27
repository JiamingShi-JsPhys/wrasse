from jinja2 import Environment

env = Environment()


def render_page(request):
    name = request.query_params.get('name', '')
    template = env.from_string(name)
    return template.render()
