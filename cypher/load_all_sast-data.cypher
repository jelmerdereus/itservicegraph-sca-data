// load SAST finding to application data
:param filename => 'https://raw.githubusercontent.com/jelmerdereus/itservicegraph-sca-data/main/data/app-sast-findings.csv';

LOAD CSV WITH HEADERS FROM $filename AS line FIELDTERMINATOR ';'
WITH line.name as software, line.app_version as version, line.date as date, line.source as source, line.severity as severity, line.cwe as cwe_ids, line.rule as rule, line.title as title, line.link as link, line.description as description, line.file as file, line.location as location, line.ref as ref
// match software
MATCH (sw:Software {swName: software, swVersion: version})
// create snapshot
MERGE (sn:Snapshot {ref: software + '_' + version + '_' + date})
ON CREATE SET sn.date = date, sn.type = 'SAST', sn.source = source
MERGE (sn)-[:SNAPSHOT_OF]-(sw)
// create findings
MERGE (fn:Finding {ref: ref})
ON CREATE SET fn.severity = severity, fn.cwe_ids = cwe_ids, fn.rule = rule, fn.title = title, fn.description = description, fn.link = link, fn.file = file, fn.location = location
MERGE (fn)-[:IDENTIFIED_IN]-(sn)
RETURN count(*)
