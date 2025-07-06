// load application to snapshot and software component data
:param filename => 'https://raw.githubusercontent.com/jelmerdereus/itservicegraph-sca-data/main/data/app-components.csv';

LOAD CSV WITH HEADERS FROM $filename AS line FIELDTERMINATOR ';'
WITH line.name AS swName, line.app_version AS swVersion, line.date AS scanDate, line.source AS source, line.component AS swComponent, line.component_version AS swComponentVer, line.purl AS purl, line.transitive AS transitive
MATCH (sw:Software {swName: swName, swVersion: swVersion})
// create/merge snapshot
MERGE (sn:Snapshot {ref: swName + '_' + swVersion + '_' + scanDate})
ON CREATE SET sn.date = scanDate, sn.type = 'SCA', sn.source = source
MERGE (sn)-[:SNAPSHOT_OF]-(sw)
// create software components
MERGE (sc:SoftwareComponent {purl: purl})
ON CREATE SET sc.component = swComponent, sc.version = swComponentVer
MERGE (sc)-[co:IDENTIFIED_IN]-(sn)
ON CREATE SET co.transitive = transitive
RETURN count(*);

// load vulnerability to software component data
:param filename => 'https://raw.githubusercontent.com/jelmerdereus/itservicegraph-sca-data/main/data/component-vulnerability.csv';

LOAD CSV WITH HEADERS FROM $filename AS line FIELDTERMINATOR ';'
WITH line.date AS date, line.source as source, line.vulnerability_id as vulnerability_id, line.purl as purl, line.severity as severity, line.title as title, line.link as link, line.status as status, line.fixed_version as fixed_version, line.published_date as published_date, line.cvss_v3 as cvss_score
MERGE (vl:Vulnerability {vulnerability_id: vulnerability_id})
ON CREATE SET vl.published = published_date, vl.source = source, vl.severity = severity, vl.title = title, vl.link = link, vl.status = status, vl.fixed_version = fixed_version, vl.cvss = cvss_score
WITH vl, purl, date
MATCH (sc:SoftwareComponent {purl: purl})
MERGE (vl)-[vo:VULNERABILITY_OF]-(sc)
ON CREATE SET vo.attributed = date
RETURN count(*);
