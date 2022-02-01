#!/usr/bin/python2

from __future__ import absolute_import
import json

_SCHEMA = u"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/" \
        u"master/Schemata/sarif-schema-2.1.0.json"
_VERSION = u"2.1.0"

class SarifBase(object):

    u"""Base class for SARIF classes."""

    def __init__(self):
        self._repr = {}

    def as_dict(self):
        u"""Returns internal representation as dict.

        :returns: Internal dictionary.

        """

        _repr = self._repr.copy()
        for k, v in _repr.items():
            if not v:
                del _repr[k]
            if isinstance(v, list):
                for i in xrange(0, len(v)):
                    if isinstance(v[i], SarifBase):
                        v[i] = v[i].as_dict()
                _repr.update({k: v})
            if isinstance(v, SarifBase):
                _repr.update({k: v.as_dict()})

        return _repr

    def __str__(self):
        return str(self.as_dict())

    def __repr__(self):
        return str(self.__str__)


class Sarif(SarifBase):

    u"""Main object representing the SARIF report."""

    def __init__(self, runs):
        u"""Initalization method.

        :runs: List of Result objects.

        """
        SarifBase.__init__(self)

        self._repr = {u"$schema": _SCHEMA,
                u"version": _VERSION,
                u"runs": runs}

    def finalize(self):
        u"""Finalize JSON output.
        :returns: SARIF output in JSON format.

        """

        try:
            return json.dumps(self.as_dict(),
                    ensure_ascii=False,
                    indent=2)
        except Exception as e:
            print e

class Run(SarifBase):

    u"""Class representing a run object in SARIF."""

    def __init__(self, tool, results):
        u"""Initalization method.

        :tool: TODO
        :results: TODO

        """
        SarifBase.__init__(self)

        self._repr = {u"tool": tool,
                u"results": results}

        def append(self, result):
            u"""Appends a result to the Run.

            :result: TODO
            :returns: TODO

            """

            self._repr[u"results"] += result



class Tool(SarifBase):

    u"""Class representing a Tool in SARIF."""

    def __init__(self, name, semantic_version, version, rules=[]):
        u"""Initalization method.

        :name: Name of the tool.
        :semantic_version: Version String
        :version: Version number as String
        :rules: Rules employed by the tool.

        """

        SarifBase.__init__(self)

        self._repr = { \
                u"driver": {
                    u"name": name,
                    u"semanticVersion": semantic_version,
                    u"version": version,
                    u"rules": rules
                } \
        }

        def append(self, rule):
            u"""Appends a rule to this tool.

            :rule: A rule in SARIF
            :returns: None

            """
            self._repr[u"rules"] += [rule]

class Result(SarifBase):

    u"""Representation of a single SARIF result."""

    def __init__(self, locations, rule_id=None, rule_index=-1,
            level=u"error", fingerprints=None, code_flows=None,
            properties=None):
        u"""Initalization method."""

        SarifBase.__init__(self)

        self._repr = {u"ruleID": rule_id,
                u"ruleIndex": rule_index,
                u"level": level,
                u"locations": locations,
                u"fingerprints": fingerprints,
                u"codeFlows": code_flows,
                u"properties": properties}

    def append(self, location):
        u"""Appends a location to the result.

        :location: A location object.
        :returns: None

        """

        self._repr[u"locations"] += [location]

class Location(SarifBase):

    u"""Representation of SARIF Locations."""

    def __init__(self, start_line, end_line, uri):
        u"""Merely works on a line base.

        :start_line: First line of defect
        :end_line: Last line of defect.

        """

        SarifBase.__init__(self)

        self._repr = {
            u"physicalLocation": { \
                u"artifactLocation": { \
                    u"uri": uri \
                },
                u"region": { \
                    u"startLine": start_line,
                    u"endLine": end_line \
                } \
            } \
        }

def test():
    u"""Test function to generate some output.
    :returns: String of SARIF output.

    """

    results = []
    for x in xrange(0, 5):
        locations = []

        for y in xrange(0, 5):
            start = randint(0, 500)
            end = randint(start, start+15)
            uri = u"/foo/bar/somefile_%d.c" % (y)

            locations += [Location(start, end, uri)]

        results.append(Result(locations))

    tool = Tool(u"FooTool", u"1.1.0", u"1.1.0")
    runs = Run(tool, results)
    sarif = Sarif([runs])

    return sarif.finalize()


if __name__ == u"__main__":
    from random import randint

    print test()




