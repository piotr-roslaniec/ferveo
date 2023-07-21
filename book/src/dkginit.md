# Initialization

Each DKG session begins by choosing a unique integer session id \\(\tau\\). This can begin at 0 and then be incremented from the previous \\(\tau\\).

# Share partitioning 

All validators should agree on a canonical ordering of \\((pk_i, w_i)\\)$ where \\(pk_i\\) is the public key of the \\(i\\)th validator and \\(w_i\\) is number of shares belonging to node \\(i\\). The value \\(i\\) is the integer id of the node with public key \\(pk_i\\).

Let \\(\Psi_{i} = \{ a, a+1, \ldots, a+w_i \}$\\) be the disjoint partition described above such that \\(\cup_i \Psi_{i} =  \{0,1, \ldots, W-1\}\\), and \\(\Omega_{i} = \{ \omega^k \ mid k \in \Psi_{i} \}\\). \\(\Psi_i\\) are the **share indexes** assigned to the \\(i\\)th validator and \\(\Omega_i\\) is the **share domain** of the \\(i\\)th validator.
