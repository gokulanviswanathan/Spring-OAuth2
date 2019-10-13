package com.hotelmgmt.auth.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The Class User.
 * 
 * @author Gokulan
 */
@Entity
@Table(name = "user")
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true, value = { "hibernateLazyInitializer", "handler" })
public class User implements Serializable {

    /**
     * The Constant serialVersionUID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The id.
     */
    @Id
    @Column(name = "id")
    private String id;

    /**
     * The name.
     */
    @Column(name = "name")
    private String name;

    /**
     * The password.
     */
    @JsonIgnore
    @Column(name = "password")
    private String password;

    /**
     * The permission.
     */
    @Column(name = "permission")
    private String permission;

    /**
     * Gets the id.
     *
     * @return the id
     */
    public String getId() {
	return id;
    }

    /**
     * Sets the id.
     *
     * @param id the new id
     */
    public void setId(String id) {
	this.id = id;
    }

    /**
     * Gets the name.
     *
     * @return the name
     */
    public String getName() {
	return name;
    }

    /**
     * Sets the name.
     *
     * @param name the new name
     */
    public void setName(String name) {
	this.name = name;
    }

    /**
     * Gets the password.
     *
     * @return the password
     */
    public String getPassword() {
	return password;
    }

    /**
     * Sets the password.
     *
     * @param password the new password
     */
    public void setPassword(String password) {
	this.password = password;
    }

    /**
     * Gets the permission.
     *
     * @return the permission
     */
    public String getPermission() {
	return permission;
    }

    /**
     * Sets the permission.
     *
     * @param permission the new permission
     */
    public void setPermission(String permission) {
	this.permission = permission;
    }

}