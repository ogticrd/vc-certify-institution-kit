// Carga un .properties como lo hace Java (ISO-8859-1 y escapes unicode con barra y «u») e imprime el valor de una clave.
// Uso: java Props.java <fichero> <clave>    (solo lo usa test/propiedades-codificacion.test.mjs, si hay `java`)
import java.io.*;
import java.util.Properties;

public class Props {
  public static void main(String[] a) throws Exception {
    Properties p = new Properties();
    try (InputStream in = new FileInputStream(a[0])) { p.load(in); }
    System.out.print(p.getProperty(a[1]));
  }
}
