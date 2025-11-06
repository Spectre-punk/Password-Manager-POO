package src.passwordManager.model;

import java.util.Objects;
import java.util.UUID;

public abstract class Entry {
    private final String id;
    private String title;
    private final EntryType type;

    public Entry(String tittle, EntryType type) {
        this.id = UUID.randomUUID().toString();
        this.type = Objects.requireNonNull(type, "type");
        setTittle(tittle);
    }

    protected void setTittle(String tittle) {
        if (tittle != null && !tittle.isEmpty()) {
            this.title = tittle;
        } else {
            System.out.println("lanzar excepcion personalizada");
        }
    }

    protected String getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    protected EntryType getType() {
        return type;
    }

    @Override
    public String toString() {
        return "Entry{id=" + id + ", title=" + title + ", type=" + type + "}";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof Entry))
            return false;
        return id.equals(((Entry) o).getId());
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
    /*
     * @Override
     * public Entry clone() {
     * try {
     * return (Entry) super.clone(); // seguro: aquí no hay secretos
     * } catch (CloneNotSupportedException e) {
     * throw new AssertionError(e);
     * }
     * }
     */
}
