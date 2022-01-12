from __future__ import absolute_import
import attr
import pandas
from sarif_om import *

VERSION = u"2.1.0"
SCHEMA = u"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

class VulnerabilityNotFoundException(Exception):
    """
        Exception raised when a Static Analysis tool reports an
        unknown exception for the table sarif_vulnerability_mapping.csv.
        Attributes:
            Tool -> The static analysis tool to report the vulnerability.
            Vulnerability -> The vulnerability reported.
    """

    def __init__(self, tool, vulnerability):
        self.message = u"Vulnerability not found on sarif_vulnerability_mapping.csv table. " \
		+ u"Tool: {}, Vulnerability: {}".format(tool, vulnerability)
        super().__init__(self.message)


class SarifHolder(object):
    def __init__(self):
        self.sarif = SarifLog(runs=[], version=VERSION, schema_uri=SCHEMA)
        self.translationDict = dict()

    # each analysis is defined by a Run
    def addRun(self, newRun):
        # Check if already exists an analysis performed by the same tool
        for run in self.sarif.runs:
            if run.tool.driver.name == newRun.tool.driver.name:
                # Append Unique Rules
                for rule in newRun.tool.driver.rules:
                    if isNotDuplicateRule(rule, run.tool.driver.rules):
                        run.tool.driver.rules.append(rule)
                # Append Unique Artifacts
                for artifact in newRun.artifacts:
                    if isNotDuplicateArtifact(artifact, run.artifacts):
                        run.artifacts.append(artifact)
                # Append Unique Logical Locations
                if newRun.logical_locations is not None:
                    for logicalLocation in newRun.logical_locations:
                        if isNotDuplicateLogicalLocation(logicalLocation, run.logical_locations):
                            run.logical_locations.append(logicalLocation)
                # Append Results
                for result in newRun.results:
                    run.results.append(result)
                return

        self.sarif.runs.append(newRun)

    # to print the analysis from a given tool
    def printToolRun(self, tool):
        run = -1L
        for i in xrange(len(self.sarif.runs)):
            if self.sarif.runs[i].tool.driver.name.lower() == tool.lower():
                run = i
        sarifIndividual = SarifLog(runs=[], version=VERSION, schema_uri=SCHEMA)
        if run != -1L:
            sarifIndividual.runs.append(self.sarif.runs[run])
        return self.serializeSarif(sarifIndividual)

    # print json formatted the SARIF file
    def do_print(self):
        return self.serializeSarif(self.sarif)

    # creates dictionary to fix variable names from sarif_om to standard sarif
    def serialize(self, inst, field, value):
        if field is not None:
            self.translationDict[field.name] = field.metadata[u'schema_property_name']
        return value

    # filters SARIF keys to discard default values in output
    def filterUnusedKeys(self, field, value):
        return not (value is None or (field.default == value and field.name != u"level") or (
                isinstance(field.default, attr.Factory) and field.default.factory() == value))

    # returns a dictionary based on the schema_property_name and the values of the SARIF object
    def serializeSarif(self, sarifObj):
        valuesDict = attr.asdict(sarifObj, filter=self.filterUnusedKeys, value_serializer=self.serialize)
        return self.recursiveSarif(valuesDict)

    # uses translationDict to fix variable names from sarif_om to standard SARIF
    def recursiveSarif(self, serializedSarif):
        if isinstance(serializedSarif, (int, str, long, unicode)):
            return serializedSarif
        if isinstance(serializedSarif, dict):
            dic = dict()
            for key, value in serializedSarif.items():
                dic[self.translationDict[key]] = self.recursiveSarif(value)
            return dic
        if isinstance(serializedSarif, list):
            lis = list()
            for item in serializedSarif:
                lis.append(self.recursiveSarif(item))
            return lis


def parseRule(tool, vulnerability, full_description=None):
    vuln_info = findVulnerabilityOnTable(tool, vulnerability)

    if full_description is None:
        return ReportingDescriptor(id=vuln_info[u"RuleId"],
                                   short_description=MultiformatMessageString(
                                       vuln_info[u"Vulnerability"]),
                                   name=vuln_info[u"Type"] + u"Vulnerability")

    return ReportingDescriptor(id=vuln_info[u"RuleId"],
                               short_description=MultiformatMessageString(
                                   vuln_info[u"Vulnerability"]),
                               full_description=MultiformatMessageString(full_description),
                               name=vuln_info[u"Type"] + u"Vulnerability")


def parseResult(tool, vulnerability, level=u"warning", uri=None, line=None, end_line=None, column=None, snippet=None,
                logicalLocation=None):
    vuln_info = findVulnerabilityOnTable(tool, vulnerability)

    level = parseLevel(level)

    locations = [
        Location(physical_location=PhysicalLocation(artifact_location=ArtifactLocation(uri=uri),
                                                    region=Region(start_line=line,
                                                                  end_line=end_line,
                                                                  start_column=column,
                                                                  snippet=ArtifactContent(text=snippet))))
    ]

    if logicalLocation is not None:
        locations[0L].logical_locations = [logicalLocation]

    return Result(rule_id=vuln_info[u"RuleId"],
                  message=Message(text=vulnerability),
                  level=level,
                  locations=locations)


def parseArtifact(uri, source_language=u"Solidity"):
    return Artifact(location=ArtifactLocation(uri=uri), source_language=source_language)


def parseLogicalLocation(name, kind=u"contract"):
    return LogicalLocation(name=name, kind=kind)


# returns the row from the table for a given vulnerability and tool
def findVulnerabilityOnTable(tool, vulnerability_found):
    table = pandas.read_csv(u"src/output_parser/sarif_vulnerability_mapping.csv")

    tool_table = table.loc[table[u"Tool"] == tool]

    # Due to messages that have extra information (for example the line where the vulnerability was found) this loop
    # will search if the vulnerability expressed on table exist inside vulnerability found
    for index, row in tool_table.iterrows():
        if row[u"Vulnerability"] in vulnerability_found or vulnerability_found in row[u"Vulnerability"]:
            return row
    raise VulnerabilityNotFoundException(tool=tool, vulnerability=vulnerability_found)


# given a level produced by a tool, returns the level in SARIF format
def parseLevel(level):
    if isinstance(level, long):
        return u"warning"
    if level.lower() == u"warning" or level.lower() == u"warnings" or level.lower() == u"medium":
        return u"warning"
    if level.lower() == u"error" or level.lower() == u"violations" or level.lower() == u"high":
        return u"error"
    if level.lower() == u"note" or level.lower() == u"conflicts" or level.lower() == u"informational":
        return u"note"
    if level.lower == u"none" or level.lower() == u"safe":
        return u"none"
    return u"warning"


# Returns True when rule is unique
def isNotDuplicateRule(newRule, rulesList):
    for rule in rulesList:
        if rule.id == newRule.id:
            return False
    return True


# Returns True when artifact is unique
def isNotDuplicateArtifact(newArtifact, artifactsList):
    for artifact in artifactsList:
        if artifact.location.uri == newArtifact.location.uri:
            return False
    return True


# Returns True when LogicalLocation is unique
def isNotDuplicateLogicalLocation(newLogicalLocation, logicalLocationList):
    for logicalLocation in logicalLocationList:
        if logicalLocation.name == newLogicalLocation.name:
            return False
    return True
