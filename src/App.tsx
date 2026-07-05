import { invoke } from "@tauri-apps/api/core";
import {
  App as AntApp,
  Badge,
  Button,
  Card,
  ConfigProvider,
  Descriptions,
  Empty,
  Input,
  Popconfirm,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
  theme
} from "antd";
import type { ColumnsType } from "antd/es/table";
import zhCN from "antd/locale/zh_CN";
import { useCallback, useEffect, useMemo, useState } from "react";

const { Text, Title } = Typography;

type PortEntry = {
  id: string;
  protocol: "TCP" | "UDP" | string;
  localAddress: string;
  localPort: number;
  remoteAddress?: string | null;
  remotePort?: number | null;
  state?: string | null;
  pid: number;
  processName: string;
  processPath?: string | null;
};

type AppStatus = {
  elevated: boolean;
  platform: string;
};

const stateColor: Record<string, string> = {
  LISTENING: "green",
  ESTABLISHED: "blue",
  TIME_WAIT: "gold",
  CLOSE_WAIT: "orange",
  SYN_SENT: "purple",
  SYN_RECEIVED: "purple"
};

function formatEndpoint(address?: string | null, port?: number | null) {
  if (!address) return "-";
  if (port === undefined || port === null) return address;
  return address + ":" + port;
}

function AppContent() {
  const { message } = AntApp.useApp();
  const [rows, setRows] = useState<PortEntry[]>([]);
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [killingPid, setKillingPid] = useState<number | null>(null);
  const [keyword, setKeyword] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [nextStatus, nextRows] = await Promise.all([
        invoke<AppStatus>("get_app_status"),
        invoke<PortEntry[]>("list_ports")
      ]);
      setStatus(nextStatus);
      setRows(nextRows);
    } catch (error) {
      message.error(String(error));
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const filteredRows = useMemo(() => {
    const q = keyword.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((row) => {
      const values = [
        row.protocol,
        row.localAddress,
        row.localPort,
        row.remoteAddress,
        row.remotePort,
        row.state,
        row.pid,
        row.processName,
        row.processPath
      ];
      return values.some((value) => String(value ?? "").toLowerCase().includes(q));
    });
  }, [keyword, rows]);

  const listeningCount = useMemo(
    () => rows.filter((row) => row.state === "LISTENING" || row.protocol === "UDP").length,
    [rows]
  );

  const processCount = useMemo(() => new Set(rows.map((row) => row.pid)).size, [rows]);

  const killProcess = async (pid: number) => {
    setKillingPid(pid);
    try {
      await invoke("kill_process", { pid });
      message.success("已结束进程 PID " + pid);
      await refresh();
    } catch (error) {
      message.error(String(error));
    } finally {
      setKillingPid(null);
    }
  };

  const columns: ColumnsType<PortEntry> = [
    {
      title: "协议",
      dataIndex: "protocol",
      width: 86,
      filters: [
        { text: "TCP", value: "TCP" },
        { text: "UDP", value: "UDP" }
      ],
      onFilter: (value, record) => record.protocol === value,
      render: (protocol) => <Tag color={protocol === "TCP" ? "processing" : "cyan"}>{protocol}</Tag>
    },
    {
      title: "本地端口",
      dataIndex: "localPort",
      width: 120,
      sorter: (a, b) => a.localPort - b.localPort,
      defaultSortOrder: "ascend",
      render: (port) => <Text strong>{port}</Text>
    },
    {
      title: "本地地址",
      dataIndex: "localAddress",
      ellipsis: true,
      render: (_, row) => <Text copyable>{formatEndpoint(row.localAddress, row.localPort)}</Text>
    },
    {
      title: "远端地址",
      dataIndex: "remoteAddress",
      ellipsis: true,
      render: (_, row) => <Text type="secondary">{formatEndpoint(row.remoteAddress, row.remotePort)}</Text>
    },
    {
      title: "状态",
      dataIndex: "state",
      width: 128,
      filters: [
        { text: "LISTENING", value: "LISTENING" },
        { text: "ESTABLISHED", value: "ESTABLISHED" },
        { text: "TIME_WAIT", value: "TIME_WAIT" },
        { text: "CLOSE_WAIT", value: "CLOSE_WAIT" }
      ],
      onFilter: (value, record) => record.state === value,
      render: (state, row) =>
        row.protocol === "UDP" ? (
          <Tag color="cyan">UDP</Tag>
        ) : state ? (
          <Tag color={stateColor[state] ?? "default"}>{state}</Tag>
        ) : (
          "-"
        )
    },
    {
      title: "PID",
      dataIndex: "pid",
      width: 110,
      sorter: (a, b) => a.pid - b.pid,
      render: (pid) => <Text copyable>{pid}</Text>
    },
    {
      title: "进程名称",
      dataIndex: "processName",
      width: 180,
      ellipsis: true,
      sorter: (a, b) => a.processName.localeCompare(b.processName)
    },
    {
      title: "路径",
      dataIndex: "processPath",
      ellipsis: true,
      render: (path) =>
        path ? (
          <Tooltip title={path}>
            <Text copyable type="secondary">
              {path}
            </Text>
          </Tooltip>
        ) : (
          <Text type="secondary">无权限读取或进程已退出</Text>
        )
    },
    {
      title: "操作",
      key: "action",
      fixed: "right",
      width: 116,
      render: (_, row) => (
        <Popconfirm
          title="结束进程"
          description={"确定结束 " + row.processName + " (PID " + row.pid + ")？"}
          okText="结束"
          cancelText="取消"
          okButtonProps={{ danger: true }}
          onConfirm={() => killProcess(row.pid)}
        >
          <Button danger size="small" loading={killingPid === row.pid}>
            结束
          </Button>
        </Popconfirm>
      )
    }
  ];

  return (
    <div className="page">
      <div className="header">
        <div>
          <Title level={2} style={{ margin: 0 }}>
            本机端口管理
          </Title>
          <Text type="secondary">Windows / macOS / Linux 本机 TCP/UDP 端口、PID、进程名称、进程路径与结束操作</Text>
        </div>
        <Space>
          <Badge status={status?.elevated ? "success" : "error"} text={status?.elevated ? "管理员权限" : "非管理员"} />
          <Button type="primary" onClick={refresh} loading={loading}>
            刷新
          </Button>
        </Space>
      </div>

      <div className="stats">
        <Card>
          <Statistic title="端口记录" value={rows.length} />
        </Card>
        <Card>
          <Statistic title="监听/UDP" value={listeningCount} />
        </Card>
        <Card>
          <Statistic title="关联进程" value={processCount} />
        </Card>
        <Card>
          <Descriptions column={1} size="small">
            <Descriptions.Item label="平台">{status?.platform ?? "-"}</Descriptions.Item>
            <Descriptions.Item label="权限">
              {status?.elevated ? <Tag color="success">已提升</Tag> : <Tag color="error">未提升</Tag>}
            </Descriptions.Item>
          </Descriptions>
        </Card>
      </div>

      <Card
        className="table-card"
        title="端口列表"
        extra={
          <Input.Search
            allowClear
            placeholder="搜索端口 / PID / 进程 / 路径 / 地址"
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            style={{ width: 360 }}
          />
        }
      >
        <Table
          rowKey="id"
          columns={columns}
          dataSource={filteredRows}
          loading={loading}
          size="middle"
          scroll={{ x: 1320 }}
          locale={{ emptyText: <Empty description="暂无端口记录" /> }}
          pagination={{
            defaultPageSize: 20,
            showSizeChanger: true,
            showTotal: (total) => "共 " + total + " 条"
          }}
        />
      </Card>
    </div>
  );
}

export default function App() {
  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: "#1677ff",
          borderRadius: 10
        }
      }}
    >
      <AntApp>
        <AppContent />
      </AntApp>
    </ConfigProvider>
  );
}
