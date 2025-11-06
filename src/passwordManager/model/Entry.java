package src.passwordManager.model;

enum EntryType {
    PASSWORD,
    NOTE,
    CREDIT_CARD,
    IDENTITY
}

public abstract class Entry {
    private String id, title;
    private static int contador;
    private EntryType type;

    public Entry(String tittle, EntryType type){
        setTittle(tittle);
        this.type = type;
        this.id = String.valueOf(contador);
        contador++;
    }

    protected void setTittle(String tittle){
        if (tittle != null && !tittle.isEmpty()) {
            this.title = tittle;
        } else{
            System.out.println("lanzar excepcion personalizada");
        }
    }
    protected String getId(){
        return id;
    }
    public String getTitle(){
        return title;
    }
    protected EntryType getType(){
        return type;
    }
    @Override
    public String toString(){
        return this.id + "," + this.title + "," + this.type;
    }
}
