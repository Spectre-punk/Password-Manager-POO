package src.passwordManager.model;

import java.time.Instant;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Collections;
import java.util.stream.Collectors;
import src.passwordManager.exceptions.DuplicateEntryException;
import src.passwordManager.exceptions.EntryNotFoundException;

public class Vault {
    private String id;
    private User owner;
    private final List<Entry> entries = new ArrayList<>();

    public Vault(User owner) {
        this.owner = owner;
    }

    public boolean addEntry(Entry e) throws DuplicateEntryException {
        for (Entry listEntry : entries) {
            if (e.getTitle().equalsIgnoreCase(listEntry.getTitle())) {
                throw new DuplicateEntryException("Duplicate entry title: " + e.getTitle());
            }
        }
        return entries.add(e);
    }

    public Entry removeEntry(String entryID) throws EntryNotFoundException {
        Iterator<Entry> iterator = entries.iterator();
        while (iterator.hasNext()) {
            Entry listEntry = iterator.next();
            if (entryID.equals(listEntry.getId())) {
                iterator.remove();
                return listEntry;
            }
        }
        throw new EntryNotFoundException("No se encontró la entrada con id: " + entryID);
    }

    public void updateEntry(Entry e) throws EntryNotFoundException {
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).getId().equals(e.getId())) {
                entries.set(i, e);
                return;
            }
        }
        throw new EntryNotFoundException("No se encontró la entrada con id: " + e.getId());
    }

    public List<Entry> listEntries() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public List<Entry> findByTitle(String title) {
        String t = title == null ? "" : title.toLowerCase();
        return entries.stream()
                .filter(e -> e.getTitle() != null && e.getTitle().toLowerCase().contains(t))
                .collect(Collectors.toList());
    }

    public List<CredentialEntry> findBySite(String site) {
        String s = site == null ? "" : site.toLowerCase();
        return entries.stream()
                .filter(e -> e instanceof CredentialEntry)
                .map(e -> (CredentialEntry) e)
                .filter(c -> c.getSite() != null && c.getSite().toLowerCase().contains(s))
                .collect(Collectors.toList());
    }

    public Entry getEntry(String id) throws EntryNotFoundException {
        for (Entry entry : entries) {
            if (id.equals(entry.getId())) {
                return entry;
            }
        }
        throw new EntryNotFoundException("No se encontró la entrada con id: " + id);
    }
}
