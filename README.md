<p align="center"><a href="https://open5gs.org" target="_blank" rel="noopener noreferrer"><img width="100" src="https://open5gs.org/assets/img/open5gs-logo-only.png" alt="Open5GS logo"></a></p>

## Getting Started

Please follow the [documentation](https://open5gs.org/open5gs/docs/) at [open5gs.org](https://open5gs.org/)!

## Fork Modifications: Blockchain Integration

This fork extends the standard Open5GS architecture to introduce blockchain signaling, Deep Packet Inspection (DPI) for blockchain-related packets, and specific application server handling. These changes were developed in the context of the accompanying engineering thesis.

### Core Network Functions
Modifications have been made to the following source directories to accommodate blockchain signaling handling:
* `/src/amf` (Access and Mobility Management Function)
* `/src/smf` (Session Management Function)
* `/src/upf` (User Plane Function)
* `/src/udm` (Unified Data Management)
* `/src/udr` (Unified Data Repository)

### Libraries & Protocols
* **PFCP (`/lib/pfcp`):** Modified to introduce blockchain-related handling in the PFCP protocol.
    * **DPI & Packet Construction:** Specifically, `/lib/pfcp/rule-match.c` includes functions for Deep Packet Inspection and building blockchain-related packets for transmission back to the User Equipment (UE).
* **SBI (`/lib/sbi`):** New blockchain-related services have been introduced here.
    * **Models (`/lib/sbi/openapi/model`):** Custom models (e.g., `sdm_blockchain...`) have been created to support the new signaling data structures.
* **DBI (`/lib/dbi`):** Modifications in `subscription.c` and `subscription.h` to support blockchain subscription data.

### Application & Services
* **Blockchain Application Server:** The implementation is provided via the `tcp_server` file.
* **Thesis Services:** Additional services described in the engineering thesis are located in the `/services` directory.

### Configuration
* **`configs/open5gs/`:** Modified configuration files to enable and tune the new blockchain features.

## Sponsors

If you find Open5GS useful for work, please consider supporting this Open Source project by [Becoming a sponsor](https://github.com/sponsors/acetcom). To manage the funding transactions transparently, you can donate through [OpenCollective](https://opencollective.com/open5gs).

<p align="center">
  <h3 align="center">Special Sponsor</h3>
</p>

<p align="center">
  <a target="_blank" href="https://mobi.com">
  <img alt="special sponsor mobi" src="https://open5gs.org/assets/img/mobi-open5GS.png" width="400">
  </a>
</p>

<p align="center">
  <a target="_blank" href="https://open5gs.org/#sponsors">
      <img alt="sponsors" src="https://open5gs.org/assets/img/sponsors.svg">
  </a>
</p>

## Community

- Problem with Open5GS can be filed as [issues](https://github.com/open5gs/open5gs/issues) in this repository.
- Other topics related to this project are happening on the [discussions](https://github.com/open5gs/open5gs/discussions).
- Voice and text chat are available in Open5GS's [Discord](https://discordapp.com/) workspace. Use [this link](https://discord.gg/GreNkuc) to get started.

## Contributing

If you're contributing through a pull request to Open5GS project on GitHub, please read the [Contributor License Agreement](https://open5gs.org/open5gs/cla/) in advance.

## License

- Open5GS Open Source files are made available under the terms of the GNU Affero General Public License ([GNU AGPL v3.0](https://www.gnu.org/licenses/agpl-3.0.html)).
- [Commercial licenses](https://open5gs.org/open5gs/support/) are also available from [NewPlane](https://newplane.io/) at [sales@newplane.io](mailto:sales@newplane.io).

## Support

Technical support and customized services for Open5GS are provided by [NewPlane](https://newplane.io/) at [support@newplane.io](mailto:support@newplane.io).
