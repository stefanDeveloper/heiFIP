from abc import ABC, abstractmethod

__author__ = "Stefan Machmeier"
__copyright__ = "Copyright 2023, heiFIP"
__credits__ = ["Manuel Trageser"]
__license__ = "EUPL"
__version__ = "0.0.1"
__maintainer__ = "Stefan Machmeier"
__email__ = "stefan.machmeier@uni-heidelberg.de"
__status__ = "Production"


class NetworkTrafficImage(ABC):
    def __init__(self, fill=0, dim=8) -> None:
        self.fill = fill
        self.dim = dim

    def __getitem__(self, i):
        return self.__dict__[i]
