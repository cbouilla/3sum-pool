from staticjinja import make_site

context = {"webservice": "52.5.252.107"}

site = make_site(contexts=[('.*', context)], outpath="output/", searchpath="templates", staticpaths=["images/", "fonts/", "css/", "static_js/"])
site.render()