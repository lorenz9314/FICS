#!/usr/bin/python2

import json

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/" \
        "master/Schemata/sarif-schema-2.1.0.json"
_VERSION = "2.1.0"

class SarifBase(object):

    """Base class for SARIF classes."""

    def __init__(self):
        self._repr = {}

    def as_dict(self):
        """Returns internal representation as dict.

        :returns: Internal dictionary.

        """

        _repr = self._repr.copy()
        for k, v in _repr.items():
            if not v:
                del _repr[k]
            if isinstance(v, list):
                for i in range(0, len(v)):
                    if isinstance(v[i], SarifBase):
                        v[i] = v[i].as_dict()
                _repr.update({k: v})
            if isinstance(v, SarifBase):
                print(v)
                _repr.update({k: v.as_dict()})

        return _repr


class Sarif(SarifBase):

    """Main object representing the SARIF report."""

    def __init__(self, runs):
        """Initalization method.

        :runs: List of Result objects.

        """
        SarifBase.__init__(self)

        self._repr = {"$schema": _SCHEMA,
                "version": _VERSION,
                "runs": runs}

    def finalize(self):
        """Finalize JSON output.
        :returns: SARIF output in JSON format.

        """

        return json.dumps(self.as_dict(),
                ensure_ascii=False,
                indent=2)

class Run(SarifBase):

    """Class representing a run object in SARIF."""

    def __init__(self, tool, results):
        """Initalization method.

        :tool: TODO
        :results: TODO

        """
        SarifBase.__init__(self)

        self._repr = {"tool": tool,
                "results": results}

        def append(self, result):
            """Appends a result to the Run.

            :result: TODO
            :returns: TODO

            """

            self._repr["results"] += result



class Tool(SarifBase):

    """Class representing a Tool in SARIF."""

    def __init__(self, name, semantic_version, version, rules=[]):
        """Initalization method.

        :name: Name of the tool.
        :semantic_version: Version String
        :version: Version number as String
        :rules: Rules employed by the tool.

        """

        SarifBase.__init__(self)

        self._repr = { \
                "driver": {
                    "name": name,
                    "semanticVersion": semantic_version,
                    "version": version,
                    "rules": rules
                } \
        }

        def append(self, rule):
            """Appends a rule to this tool.

            :rule: A rule in SARIF
            :returns: None

            """
            self._repr["rules"] += [rule]

class Result(SarifBase):

    """Representation of a single SARIF result."""

    def __init__(self, locations, rule_id=None, rule_index=-1,
            level="error", fingerprints=None, code_flows=None,
            properties=None):
        """Initalization method."""

        SarifBase.__init__(self)

        self._repr = {"ruleID": rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "locations": locations,
                "fingerprints": fingerprints,
                "codeFlows": code_flows,
                "properties": properties}

    def append(self, location):
        """Appends a location to the result.

        :location: A location object.
        :returns: None

        """

        self._repr["locations"] += [location]

class Location(SarifBase):

    """Representation of SARIF Locations."""

    def __init__(self, start_line, end_line, uri):
        """Merely works on a line base.

        :start_line: First line of defect
        :end_line: Last line of defect.

        """

        SarifBase.__init__(self)

        self._repr = {
            "physicalLocation": { \
                "artifactLocation": { \
                    "uri": uri \
                },
                "region": { \
                    "startLine": start_line,
                    "endLine": end_line \
                } \
            } \
        }

def test():
    """Test function to generate some output.
    :returns: String of SARIF output.

    """

    results = []
    for x in range(0, 5):
        locations = []

        for y in range(0, 5):
            start = randint(0, 500)
            end = randint(start, start+15)
            uri = "/foo/bar/somefile_%d.c" % (y)

            locations += [Location(start, end, uri)]

        results.append(Result(locations))

    tool = Tool("FooTool", "1.1.0", "1.1.0")
    runs = Run(tool, results)
    sarif = Sarif([runs])

    return sarif.finalize()


if __name__ == "__main__":
    from random import randint

    print(test())




