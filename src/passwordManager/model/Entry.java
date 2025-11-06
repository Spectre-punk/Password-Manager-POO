package src.passwordManager.model;

enum EntryType {
    PASSWORD,
    NOTE,
    CREDIT_CARD,
    IDENTITY
}

public abstract class Entry {
    private String id, tittle;
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
            this.tittle = tittle;
        } else{
            System.out.println("lanzar excepcion personalizada");
        }
    }
    protected String getId(){
        return id;
    }
    protected String getTittle(){
        return tittle;
    }
    protected EntryType getType(){
        return type;
    }

}
