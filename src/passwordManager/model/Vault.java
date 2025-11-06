package src.passwordManager.model;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator; // Import Iterator
import src.passwordManager.exceptions.PasswordManagerException;

public class Vault {
    String id;
    User owner;
    List<Entry> entries = new ArrayList<>();

    protected Vault(User owner) {
        this.owner = owner;
    }

    protected boolean addEntry(Entry e) {
        for (Entry list_entry : entries) {
            if (e.getTitle().equals(list_entry.getTitle())) {
                // lanzar excepcion
                return false;
            }
        }
        entries.add(e);
        return true;
    }

    protected void removeEntry(String entryID) throws PasswordManagerException {
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
        throw new PasswordManagerException("Not found the id:" + entryID);
    }  

    protected void updateEntry(Entry e) {

    }

    protected List<Entry> findByTitle(String title) throws PasswordManagerException {
        List<Entry> matchingEntries = new ArrayList<>();
        Iterator<Entry> iterator = entries.iterator();

        while (iterator.hasNext()) {
            Entry list_entry = iterator.next();
            if (title != null && title.equals(list_entry.getTitle())) { // Compare with title, not ID
                matchingEntries.add(list_entry);
            }
        }
        if (matchingEntries.isEmpty()) {
            throw new PasswordManagerException("title not found:" + title);
        }
        return matchingEntries; 
    }

    protected List<Entry> listEntries() {
        return entries;
    }

    protected Entry getEntry(String id) throws PasswordManagerException {
        for (Entry entry : entries) {
            if (id.equals(entry.getId())) {
                return entry;
            }
        }
        throw new PasswordManagerException("Id not found:" + id);
    }
    /*
     * exportToPlainStructure() — devuelve una estructura serializable (por ejemplo
     * Map o un DTO) sin revelar secretos descifrados (solo meta). Útil para
     * StorageManager.
     * 
     */
}
