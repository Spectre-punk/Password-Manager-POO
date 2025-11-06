package src.passwordManager.model;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator; // Import Iterator
import src.passwordManager.exceptions.PasswordManagerException;

public class Vault {
    Vault id;
    User owner;
    List<Entry> entries = new ArrayList<>();

    protected Vault(User owner){
        this.owner = owner;
    }
    protected boolean addEntry(Entry e){
        for (Entry list_entry : entries) {
            if (e.getTittle() == list_entry.getTittle()) {
                // lanzar excepcion
                return false;
            }
        }
        entries.add(e);
        return true;
    }
    protected void removeEntry(String entryID) throws PasswordManagerException{
        Iterator<Entry> iterator = entries.iterator(); // Create an iterator
        while (iterator.hasNext()) {
            Entry list_entry = iterator.next();
            if (entryID.equals(list_entry.getId())) { // Use equals for string comparison
                // lanzar excepcion
                iterator.remove(); // Safely remove the entry
                return; // Exit after removing
            }
        }
        // lanzar excepcion
        throw new PasswordManagerException("Not found the id");
    }
    protected void updateEntry(Entry e){

    }
    protected String findByTitle(String title){

    }
}
