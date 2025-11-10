package com.detailo.identity_service.models;

import jakarta.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true, nullable = false)
    private String name; // e.g., "ROLE_OWNER", "ROLE_CLIENT"

    // Constructors

    public Role() {
    }

    public Role(String name) {
        this.name = name;
    }

    // Getters and Setters

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    // Note: No setName() method - 'name' should be set only via constructor
    // to maintain immutability and prevent breaking hash-based collection contracts.
    // JPA will set the field directly via reflection when loading from the database.

    // equals and hashCode
    // Note: Uses 'id' field instead of 'name' to ensure stability in hash-based collections.
    // For transient entities (id == null), object identity is used.

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        // Use id for equality if both entities are persisted (id != null)
        // For transient entities, fall back to object identity (handled by == check above)
        return id != null && role.id != null && Objects.equals(id, role.id);
    }

    @Override
    public int hashCode() {
        // Use id for hashCode if persisted, otherwise use object identity
        return id != null ? Objects.hash(id) : System.identityHashCode(this);
    }

    // toString

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
