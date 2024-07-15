#  Reverse proxy api
#  Copyright © 2022-2024 ICOS Consortium
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  This work has received funding from the European Union's HORIZON research 
#  and innovation programme under grant agreement No. 101070177.


from dataclasses import dataclass
from typing import Callable, Generic, Self, TypeVar, Union, assert_never, cast

T = TypeVar("T")
E = TypeVar("E")
T2 = TypeVar("T2")

@dataclass
class Result(Generic[T, E]):
    item: Union[T, None]
    err: Union[E, None]

    def unwrap(self):
        if self.item is None:
            raise RuntimeError("Item is None")

        return cast(T, self.item)

    def has_item(self):
        return self.item is not None

    def has_error(self):
        return self.err is not None

    def map_item(self, cal: Callable[[T], T2]) -> "Result[T2, E]":
        if not self.has_item():
            return Result(None, self.err)
        
        item = cast(T, self.item)
        mapped_item = cal(item)

        return Result(mapped_item, None)
        