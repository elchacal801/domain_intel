import { useParams } from 'react-router-dom';
export default function DomainDetail() {
  const { domain } = useParams();
  return <div className="text-gray-400">Investigating: {domain}</div>;
}
