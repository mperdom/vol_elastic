# Marco Perdomo
# Final Project Code
# Foundation code base taken from https://dolosdev.com/volatility-elasticsearch-renderer/

from datetime import datetime
# import the elasticsearch package
# must first pip install elasticsearch
# error out if package is not installed
try:
  from elasticsearch import Elasticsearch
  from elasticsearch import helpers
except ImportError:
  Elasticsearch = None
from volatility.renderers.basic import Renderer, Bytes
from volatility import debug
import uuid


class ElasticRenderer(Renderer):
    """Class sets up the renderer for Elasticsearch
    """

    def __init__(self, plugin_name, config):
        # error out if Elasticsearch python client has not been installed
        if not Elasticsearch:
            debug.error("You must install the Elasticsearch python client" \
                    ":\n\thttps://pypi.org/project/elasticsearch/")
        self._plugin_name = plugin_name
        self._config = config
        self._es = None
        self._type = 'volatility'
        self._accumulator = []

    def render(self, outfd, grid):
        self._es = Elasticsearch([self._config.ELASTIC_URL])

        # multiple rows will be created for each output row that the plugin produces
        def _add_multiple_row(node, accumulator):
            row = node.values._asdict()
            if 'start' in row and row['start'][:-5] != '':
                row['datetime'] = datetime.strptime(row['start'][:-5],"%Y-%m-%d %H:%M:%S %Z")
            else:
                row['datetime'] = datetime.now()
            # define each plugin count as a row
            row['plugin'] = self._plugin_name
            accumulator.append({
                '_index': self._config.INDEX,
                '_type': self._type,
                '_id': uuid.uuid4().hex,
                '_source': row
                })
            # if there are more than 500 counts of a plugin, handle them in bulks
            if len(accumulator) > 500:
                helpers.bulk(self._es, accumulator)
                accumulator = []
            self._accumulator = accumulator
            return accumulator
        # populate the grid with each count of a plugin
        grid.populate(_add_multiple_row, self._accumulator)

        #Insert last nodes
        if len(self._accumulator) > 0:
            helpers.bulk(self._es, self._accumulator)
