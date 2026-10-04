// Renderiza una plantilla como lo hace Certify (VelocityTemplatingEngineImpl.format): VelocityContext sobre un mapa
// con las variables, y `_esc` = EscapeTool (velocity-tools-generic 3.1) con velocity 1.7: las versiones del pom de
// certify-service. Uso:  java -cp <jars> RenderVelocity.java <plantilla.vm> [clave valor]...   (valor __NULL__ = null)
// Solo lo usa test/plantilla-velocity.test.mjs, cuando KIT_VELOCITY_CP apunta a los jars (el CI los baja de Maven Central).
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.tools.generic.EscapeTool;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class RenderVelocity {
  public static void main(String[] a) throws Exception {
    String tpl = new String(Files.readAllBytes(Paths.get(a[0])), "UTF-8");
    Map<String, Object> m = new HashMap<>();
    for (int i = 1; i + 1 < a.length; i += 2) m.put(a[i], a[i + 1].equals("__NULL__") ? null : a[i + 1]);
    m.put("_esc", new EscapeTool());
    m.putIfAbsent("_issuer", "did:web:emisor.prueba.invalid");
    m.putIfAbsent("_holderId", "did:jwk:titular-de-prueba");
    m.putIfAbsent("validFrom", "2026-01-01T00:00:00Z");
    m.putIfAbsent("validUntil", "2027-01-01T00:00:00Z");
    VelocityEngine e = new VelocityEngine();
    e.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
    e.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
    e.init();
    StringWriter w = new StringWriter();
    e.evaluate(new VelocityContext(m), w, "plantilla", tpl);
    System.out.write(w.toString().getBytes("UTF-8"));
    System.out.flush();
  }
}
