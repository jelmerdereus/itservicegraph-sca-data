// Indexes and Unique Constraints
// To run the following in Neo4j Workspace (AuraDB), remove the remarks and run only the Cypher statements!
CREATE CONSTRAINT networkComponentUnique FOR (n:NetworkComponent) REQUIRE (n.assetNr) IS UNIQUE;
CREATE CONSTRAINT serverAssetUnique FOR (n:Server) REQUIRE (n.assetNr) IS UNIQUE;

CREATE CONSTRAINT subNetIPExists FOR (n:SubNet) REQUIRE n.subnetIP IS NOT NULL;
CREATE CONSTRAINT subNetMaskExists FOR (n:SubNet) REQUIRE n.subnetMask IS NOT NULL;
CREATE CONSTRAINT customerNameExists FOR (n:Customer) REQUIRE n.customerName IS NOT NULL;
CREATE CONSTRAINT serviceOwnerExists FOR (n:Service) REQUIRE n.serviceOwner IS NOT NULL;
CREATE CONSTRAINT serviceNameExists FOR (n:Service) REQUIRE n.serviceName IS NOT NULL;

CREATE CONSTRAINT dcSecNameExists FOR (n:Section) REQUIRE n.dcSecName IS NOT NULL;
CREATE CONSTRAINT swNameExists FOR (n:Software) REQUIRE n.swName IS NOT NULL;

CREATE CONSTRAINT leaseEndExists FOR (n:NetworkComponent) REQUIRE n.leaseEnd IS NOT NULL;
CREATE CONSTRAINT installDateExists FOR (n:NetworkComponent) REQUIRE n.installDate IS NOT NULL;
CREATE CONSTRAINT assetNrExistsNet FOR (n:NetworkComponent) REQUIRE n.assetNr IS NOT NULL;
CREATE CONSTRAINT serverNameExists FOR (n:Server) REQUIRE n.serverName IS NOT NULL;
CREATE CONSTRAINT assetNrExistsSvr FOR (n:Server) REQUIRE n.assetNr IS NOT NULL;

CREATE CONSTRAINT uniqueRefNotNull FOR (n:Snapshot) REQUIRE n.ref IS NOT NULL;
CREATE CONSTRAINT uniqueRefNotNull FOR (n:Snapshot) REQUIRE n.type IS NOT NULL;
CREATE CONSTRAINT uniqueRefExists FOR (n:Snapshot) REQUIRE n.ref IS UNIQUE;

CREATE CONSTRAINT purlNotNull FOR (n:SoftwareComponent) REQUIRE n.purl IS NOT NULL;
CREATE CONSTRAINT purlExists FOR (n:SoftwareComponent) REQUIRE n.purl IS UNIQUE;

CREATE CONSTRAINT vulnRefExists FOR (n:Vulnerability) REQUIRE n.vulnerability_id IS NOT NULL;
CREATE CONSTRAINT vulnRefUnique FOR (n:Vulnerability) REQUIRE n.vulnerability_id IS UNIQUE;

CREATE CONSTRAINT fnRefExists FOR (n:Finding) REQUIRE n.ref IS NOT NULL;
CREATE CONSTRAINT fnRefUNique FOR (n:Finding) REQUIRE n.ref IS UNIQUE;

// Indexes
CREATE INDEX IF NOT EXISTS FOR (n:Customer) ON (n.customerName);
CREATE INDEX IF NOT EXISTS FOR (n:Service) ON (n.serviceOwner);
CREATE INDEX IF NOT EXISTS FOR (n:Service) ON (n.serviceName);
CREATE INDEX IF NOT EXISTS FOR (n:Software) ON (n.swFirstSeen);
CREATE INDEX IF NOT EXISTS FOR (n:Software) ON (n.swLastUpdate);
CREATE INDEX IF NOT EXISTS FOR (n:Software) ON (n.swName);
CREATE INDEX IF NOT EXISTS FOR (n:NetworkComponent) ON (n.modelName);
CREATE INDEX IF NOT EXISTS FOR (n:Server) ON (n.serverName);
CREATE INDEX IF NOT EXISTS FOR (n:Snapshot) ON (n.date);
CREATE INDEX IF NOT EXISTS FOR (n:Snapshot) ON (n.source);
CREATE INDEX IF NOT EXISTS FOR (n:Snapshot) ON (n.type);
CREATE INDEX IF NOT EXISTS FOR (n:SoftwareComponent) ON (n.component);
CREATE INDEX IF NOT EXISTS FOR (n:SoftwareComponent) ON (n.version);
CREATE INDEX IF NOT EXISTS FOR (n:SoftwareComponent) ON (n.purl);
CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.vulnerability_id);
CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.severity);
CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.title);
CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.cvss);
CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.source);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.severity);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.cwe_ids);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.rule);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.title);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.description);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.link);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.file);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.location);
CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.source);
