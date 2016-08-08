package ma.inov.sigtranAnalyser.DB;

import static ma.inov.sigtranAnalyser.mainClasses.Main.jTable1;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.mongo.MongoClient;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MongoVerticle extends AbstractVerticle {

    @Override
    public void start() throws Exception {

        Logger mongoLogger = Logger.getLogger("org.mongodb.driver");
        mongoLogger.setLevel(Level.SEVERE);

        JsonObject config = Vertx.currentContext().config();

        String uri = config.getString("MongoDB://localhost");
        if (uri == null) {
            uri = "mongodb://localhost:27017";
        }
        String db = config.getString("SignalingPoint1");
        if (db == null) {
            db = "SignalingPoint1";
        }

        JsonObject mongoconfig = new JsonObject()
                .put("connection_string", uri)
                .put("db_name", db);

        MongoClient mongoClient = MongoClient.createNonShared(vertx, mongoconfig);

        int rows = jTable1.getRowCount();
        for (int row = 0; row < rows; row++) {
            JsonObject query = new JsonObject()
                    .put("Adaptation", jTable1.getValueAt(row, 0))
                    .put("Layer", jTable1.getValueAt(row, 1))
                    .put("OPC", jTable1.getValueAt(row, 2))
                    .put("DPC", jTable1.getValueAt(row, 3))
                    .put("NI", jTable1.getValueAt(row, 4))
                    .put("Source IP Address", jTable1.getValueAt(row, 5))
                    .put("Source Port", jTable1.getValueAt(row, 6))
                    .put("Destination IP", jTable1.getValueAt(row, 7))
                    .put("Destination Port", jTable1.getValueAt(row, 8))
                    .put("VLAN", jTable1.getValueAt(row, 9));

            mongoClient.insert("products", query, res -> {

                 //  if (res.succeeded()) {
                 //  String id = res.result();
                 //  System.out.println("Inserted book with id " + id);
                 // } else {
                 //  res.cause().printStackTrace();
                 //  }
           });
        }//if
         
    }
}

/*
        Vertx vertx = Vertx.vertx();
        
        DeploymentOptions options = new DeploymentOptions().setWorker(true);
        options.setHa(true);

        //deploy our sender
        vertx.deployVerticle(new MongoVerticle(), options);

*/  