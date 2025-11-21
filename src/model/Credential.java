package model;

import crypto.CifradoUtil;

public class Credential {

    private String servicio; // pagina relacionada a la contraseña (google, discord, apple)
    private String nombreUsuario; // correo o usuario 
    private String contraseñaCifrada;
    private String notas;

    // constructores
    public Credential(String servicio, String nombreUsuario, String inputPassword, String notas) {
        this.servicio = servicio;
        this.nombreUsuario = nombreUsuario;
        this.notas = notas;
        try {
            this.contraseñaCifrada = CifradoUtil.encrypt(inputPassword);
        } catch (Exception e) {
            throw new IllegalStateException("Failded to encrypt password for service" + servicio, e);
        }
    }

    public String getServicio() {
        return this.servicio;
    }

    public void setServicio(String servicio) {
        this.servicio = servicio;
    }

    public String getNombreUsuario() {
        return this.nombreUsuario;
    }

    public void setNombreUsuario(String nombreUsuario) {
        this.nombreUsuario = nombreUsuario;
    }

    public String getContraseñaCifrada() {
        return this.contraseñaCifrada;
    }

    public String getNotas() {
        return notas;
    }

    public void setNotas(String notas) {
        this.notas = notas;
    }

    @Override
    public String toString() {
        return "servicio:" + servicio
                + "\nnombre de usuario:" + nombreUsuario
                + "\nnotas:" + notas
                + "\ncontraseña:" + CifradoUtil.decrypt(contraseñaCifrada);
    }
}
