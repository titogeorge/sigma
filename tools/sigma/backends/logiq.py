import re

import yaml

from .base import SingleTextQueryBackend
import json


class LogiqBackend(SingleTextQueryBackend):
    """Converts Sigma rule into LOGIQ event rule api payload """
    identifier = "logiq"
    config_required = False
    active = True
    reEscape = re.compile('(")')
    reClear = None
    andToken = " && "
    orToken = " || "
    notToken = " !~ "
    subExpression = "%s"
    listExpression = "%s"
    listSeparator = ", "
    valueExpression = "message =~ \'%s\'"
    keyExpression = "%s"
    nullExpression = "!~ %s"
    notNullExpression = "!%s"
    mapExpression = "(%s=%s)"
    mapListsSpecialHandling = True

    reEscape = re.compile("([\\|()\[\]{}.^$+])")

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""

        event_rule = dict()

        title = re.sub('[^a-zA-Z0-9]', '_', sigmaparser.parsedyaml["title"])

        event_rule["name"] = title.lower()
        group = sigmaparser.parsedyaml["logsource"].get("service", "")
        if len(group) == 0:
            group = sigmaparser.parsedyaml["logsource"].get("product", "")
        if len(group) == 0:
            group = sigmaparser.parsedyaml["logsource"].get("category", "")

        event_rule["groupName"] = group
        event_rule["description"] = sigmaparser.parsedyaml["description"]
        event_rule["condition"] = sigmaparser.parsedyaml["detection"]
        event_rule["level"] = sigmaparser.parsedyaml["level"]
        tags = sigmaparser.parsedyaml.get("tags", "")
        if len(tags) > 0:
            tags_dict = dict()
            for tag in tags:
                splits = tag.split(".")
                for split in splits:
                    tags_dict[split] = 1
            tag_str = ""
            for e in tags_dict:
                if len(tag_str) == 0:
                    tag_str = e
                else:
                    tag_str = tag_str + "," + e

            event_rule["tags"] = tag_str

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            event_rule["condition"] = ""
            if before is not None:
                event_rule["condition"] = before
            if query is not None:
                event_rule["condition"] += query
            if after is not None:
                event_rule["condition"] += after

            return json.dumps(event_rule)

    def cleanValue(self, val):
        if type(val) == str:
            cleaned = re.sub('[^a-zA-Z0-9.=]', '.*', val)
            return cleaned.replace(".*.*", ".*")

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.generateORNode(node)

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return generated.replace("=~", "!~")
        else:
            return None

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling is False and type(value) in (str, int, list) or self.mapListsSpecialHandling is True and type(value) in (str, int):
            if type(value) == str:
                if "*" in value:
                    return "([%s] =~ ['%s'])" % (key, self.cleanValue(value))
                else:
                    return "([%s] == ['%s'])" % (key, value)
            elif type(value) == int:
                return "([%s] == %s)" % (key, value)
            elif type(value) == list:
                return self.generateMapItemListNode(key, value)
            else:
                return self.mapExpression % (key, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        elif value is None:
            return None
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        setitems = list()
        for item in value:
            if type(item) == str:
                setitems.append("([%s] =~ ['%s'])" % (key, self.cleanValue(item)))
            elif type(item) == int:
                setitems.append("([%s] == %s)" % (key, item))
            else:
                setitems.append("([%s] =~ ['%s'])" % (key, self.cleanValue(item)))

        query = "(" + " || ".join(filter(None, setitems)) + ")"
        return query

