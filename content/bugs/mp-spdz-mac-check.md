---
title: "MP-SPDZ MAC-check leakage under multithreading"
date: 2023-07-21
primitives: [mac, commitment]
repository: https://github.com/data61/MP-SPDZ
source:
  - name: "Rushing at SPDZ, ePrint 2025/789"
    url: https://eprint.iacr.org/2025/789.pdf
---

In MP-SPDZ, the concrete synchronization point is `Commit_And_Open_`, the helper
used by the MAC check to commit to local check values and then open them. Before
the fix, each thread ran this helper independently. There was no coordinator
shared across concurrent MAC checks, so one stalled check did not block another
thread using the same global MAC key
([source](https://github.com/data61/MP-SPDZ/blob/e08a6adb63ea057338f5613645d9d498cb43f2a9/Tools/Subroutines.cpp#L153-L169)):

```cpp
// FILE: Tools/Subroutines.cpp — MP-SPDZ (vulnerable, before 6a42453)
void Commit_And_Open_(vector<octetStream>& datas, const Player& P)
{
  vector<octetStream> Comm_data(P.num_players());
  vector<octetStream> Open_data(P.num_players());

  Commit(Comm_data[P.my_num()], Open_data[P.my_num()], datas[P.my_num()],
      P.my_num());
  P.Broadcast_Receive(Comm_data);

  P.Broadcast_Receive(Open_data);

  for (int i = 0; i < P.num_players(); i++)
    { if (i != P.my_num())
        { if (!Open(datas[i], Comm_data[i], Open_data[i], i))
             { throw invalid_commitment(); }
        }
    }
}
```

The [Rushing at SPDZ](https://eprint.iacr.org/2025/789.pdf) paper cites
commits [`6a42453`](https://github.com/data61/MP-SPDZ/commit/6a424539c93f) and
[`b86f29b`](https://github.com/data61/MP-SPDZ/commit/b86f29b69515) as the
MP-SPDZ fix. The final version passes a shared `Coordinator` into
`Commit_And_Open_`, waits before the opening phase, validates every opening, and
only then calls `coordinator.finished()`
([source](https://github.com/data61/MP-SPDZ/blob/b86f29b69515cfe0d925dfb07136b5b03e9a96d2/Tools/Subroutines.cpp#L153-L172)):

```cpp
// FILE: Tools/Subroutines.cpp — MP-SPDZ (fixed, commit b86f29b)
void Commit_And_Open_(vector<octetStream>& datas, const Player& P,
        Coordinator& coordinator)
{
  vector<octetStream> Comm_data(P.num_players());
  vector<octetStream> Open_data(P.num_players());

  Commit(Comm_data[P.my_num()], Open_data[P.my_num()], datas[P.my_num()],
      P.my_num());
  P.Broadcast_Receive(Comm_data);

  coordinator.wait(P.get_id());
  P.Broadcast_Receive(Open_data);

  for (int i = 0; i < P.num_players(); i++)
    { if (i != P.my_num())
        { if (!Open(datas[i], Comm_data[i], Open_data[i], i))
             { throw invalid_commitment(); }
        }
    }

  coordinator.finished();
}
```

Holding the coordinator until validation completes serializes the MAC-check
opening path: a stalled or invalid MAC check prevents other threads from
continuing under the same key.
