//! Example main on how to use the lcsf lib
//!
//! author: Jean-Roland Gosse
//!
//! This file is part of LCSF Stack Rust.
//! Spec details at <https://jean-roland.github.io/LCSF_Doc/>
//! You should have received a copy of the GNU Lesser General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>

mod lcsf_lib;
mod lcsf_prot;
mod packet;

/// Main function
fn main() {
    println!("*** Main start ***");
    packet::example_use_gen();
    packet::example_use_other();
    println!("*** Main end ***");
}
