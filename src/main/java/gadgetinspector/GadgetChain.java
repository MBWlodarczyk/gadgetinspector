package gadgetinspector;

import java.util.List;
import java.util.ArrayList;
import java.io.Writer;
import java.io.IOException;

class GadgetChain {
   public final List<GadgetChainLink> links;
   public GadgetChain.Type type;

   public enum Type {
      RCE, FILE, NET, INVOKE, UNKNOWN
   }

   public GadgetChain(List<GadgetChainLink> links) {
      this.links = links;
      this.type = GadgetChain.Type.UNKNOWN;
   }

   public GadgetChain(GadgetChain gadgetChain, GadgetChainLink link) {
      List<GadgetChainLink> links = new ArrayList<GadgetChainLink>(gadgetChain.links);
      links.add(link);
      this.links = links;
      this.type = GadgetChain.Type.UNKNOWN;
   }

   public void write(Writer writer) throws IOException {
      writer.write(String.format("%s type gadget%n", this.type.toString()));
      writer.write(String.format("%s.%s%s (%d)%n",
               this.links.get(0).method.getClassReference().getName(),
               this.links.get(0).method.getName(),
               this.links.get(0).method.getDesc(),
               this.links.get(0).taintedArgIndex));
      for (int i = 1; i < this.links.size(); i++) {
         writer.write(String.format("  %s.%s%s (%d)%n",
                  this.links.get(i).method.getClassReference().getName(),
                  this.links.get(i).method.getName(),
                  this.links.get(i).method.getDesc(),
                  this.links.get(i).taintedArgIndex));
      }
      writer.write("\n");
   }

}
