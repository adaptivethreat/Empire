""" Provides helper methods for templating.
This is useful for generating stagers """

import jinja2

class TemplateEngine(object):
    def __init__(self, path):
        self.template_dir = path
        self.env = self.create_environment(path)

    def create_environment(self, path):
        """
        path - Either a single string or an array of strings specifying the
               path to the directory containg the  template(s) to be used. The
               specified directory and all subdirectories will be searched for
               templates. For other ways to search for and load templates
               see http://jinja.pocoo.org/docs/2.10/api/#loaders
        """
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(path),
            comment_start_string='"""',
            comment_end_string='"""',
            line_comment_prefix="#",
        )

        # Register custom jinja2 filters
        # see "Custom jinja2 filters" section below
        env.filters['notrailingslash'] = filter_notrailingslash
        env.filters['noleadingslash'] = filter_noleadingslash
        env.filters['ensuretrailingslash'] = filter_ensuretrailingslash
        env.filters['ensureleadingslash'] = filter_ensureleadingslash

        return env

    def get_template(self, filename):
        """
        fetch and return a jinja2 template object
        see: http://jinja.pocoo.org/docs/2.10/api/#jinja2.Template

        filename - the path to the template, relative to the path passed to the
                   jinja2 environment when it was created (e.g. if
                   create_environment was called with ('/foo/') then passing
                   'bar.txt' to get_template will look for a template named
                   '/foo/bar.txt')
        """
        return self.env.get_template(filename)


###### Custom jinja2 filters ######
# Need to be registered (see "Register custom jinja2 filters" above)
# see: http://jinja.pocoo.org/docs/2.10/api/#custom-filters

def filter_notrailingslash(host):
    """
    Removes a trailing slash from URLs (or anything, really)
    Usage: {{ 'www.example.com/' | notrailingslash }}
    Output: 'www.example.com'
    """
    if host.endswith("/"):
        host = host[0:-1]
    return host

def filter_noleadingslash(host):
    """
    Removes a leading slash from URLs (or anything, really)
    Usage: {{ '/login.php' | noleadingslash }}
    Output: 'login.php'
    """
    if host.startswith("/"):
        host = host[1:]
    return host

def filter_ensuretrailingslash(host):
    """
    Adds a trailing slash to URLs (or anything, really) if one isn't present
    Usage: {{ 'www.example.com' | ensuretrailingslash }}
    Output: 'www.example.com/'
    """
    if not host.endswith("/"):
        host = host + "/"
    return host

def filter_ensureleadingslash(host):
    """
    Adds a leading slash to URLs (or anything, really) if one isn't present
    Usage: {{ 'login.php' | ensureleadingslash }}
    Output: '/login.php'
    """
    if not host.startswith("/"):
        host = "/" + host
    return host
